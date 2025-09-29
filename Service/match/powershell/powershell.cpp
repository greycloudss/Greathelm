#include "powershell.h"
#include "../../escalate/defender.h"

namespace MATCH {
    static std::string take_b64_arg(const std::string& s) {
        std::string low = UTIL::to_lower(s);
        size_t p = low.find("-enc");
        if (p == std::string::npos) p = low.find("-encodedcommand");
        if (p == std::string::npos) return {};
        size_t i = p;
        while (i < s.size() && !isspace((unsigned char)s[i])) ++i;
        while (i < s.size() &&  isspace((unsigned char)s[i])) ++i;
        size_t j = i;
        while (j < s.size() && !isspace((unsigned char)s[j])) ++j;
        if (j <= i) return {};
        return s.substr(i, j - i);
    }

    bool evaluate(const void* p, size_t n) {
        const unsigned char* s = (const unsigned char*)p;
        for (size_t i = 0; i < n; ++i) if (s[i] == 'I') return false;
        return true;
    }

    std::string Powershell::matchCommands(std::string command) {
        std::string key = UTIL::stripSpaces(command);
        std::unordered_map<std::string, std::string>::const_iterator it = psStrings.find(key);
        if (it != psStrings.end()) return it->second;
        key = UTIL::slashFlag(key);
        it = psStrings.find(key);
        if (it != psStrings.end()) return it->second;
        for (const auto& kv : psStrings) if (UTIL::to_lower(key).find(kv.first) != std::string::npos) return kv.second;
        return "";
    }

    std::string Powershell::decode(std::string command) {
        std::string arg = take_b64_arg(command);
        if (!arg.empty()) {
            std::string d = UTIL::b64decode(arg);
            if (!d.empty()) return matchCommands(d);
        }
        return matchCommands(UTIL::b64decode(command));
    }

    DWORD WINAPI AmsiPolicyServer(LPVOID pv) {
        MATCH::Powershell* self = (MATCH::Powershell*)pv;

        SECURITY_DESCRIPTOR sd; InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
        SECURITY_ATTRIBUTES sa{ sizeof(sa), &sd, FALSE };

        for (;;) {
            HANDLE h = CreateNamedPipeW(LR"(\\.\pipe\AmsiPolicy)", PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa);
            if (h == INVALID_HANDLE_VALUE) return 0;

            BOOL ok = ConnectNamedPipe(h, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (!ok) { CloseHandle(h); continue; }

            DWORD need=0, got=0;
            if (!ReadFile(h, &need, sizeof need, &got, nullptr) || got != sizeof need) { DisconnectNamedPipe(h); CloseHandle(h); continue; }

            constexpr DWORD kMax = 262144;
            const DWORD want = need, take = want > kMax ? kMax : want;

            std::vector<char> buf(take);
            DWORD off = 0;
            while (off < take) { DWORD r=0; if (!ReadFile(h, buf.data()+off, take-off, &r, nullptr) || r==0) break; off += r; }

            DWORD drained = off; char sink[65536];
            while (drained < want) {
                DWORD toRead = (want - drained > sizeof(sink)) ? sizeof(sink) : (want - drained);
                DWORD r=0; if (!ReadFile(h, sink, toRead, &r, nullptr) || r==0) break; drained += r;
            }

            char verdict = 'A';
            if (off && self) {
                std::string cmd;
                if (off >= 2 && (unsigned char)buf[1] == 0x00) {
                    const wchar_t* ws = reinterpret_cast<const wchar_t*>(buf.data());
                    int wlen = (int)(off / 2);
                    int need8 = WideCharToMultiByte(CP_UTF8, 0, ws, wlen, nullptr, 0, nullptr, nullptr);
                    if (need8 > 0) { cmd.resize(need8); WideCharToMultiByte(CP_UTF8, 0, ws, wlen, &cmd[0], need8, nullptr, nullptr); }
                } else {
                    cmd.assign(buf.data(), buf.data() + off);
                }

                std::string norm, sNorm;
                norm.reserve(cmd.size());

                norm = UTIL::to_lower(UTIL::stripSpaces(cmd));
                sNorm = UTIL::slashFlag(norm);

                std::string reason;
                for (const auto& kv : MATCH::Powershell::psStrings) {
                    if (norm.find(kv.first) != std::string::npos || sNorm.find(UTIL::slashFlag(kv.first)) != std::string::npos){
                        reason = kv.second;
                        break;
                    }
                }

                if (reason.empty()) {
                    std::string dec = self->decode(cmd);
                    if (!dec.empty())
                        reason = dec;

                    dec = UTIL::slashFlag(dec);
                    if (!dec.empty())
                        reason = dec;
                }

                if (!reason.empty()) {
                    verdict = 'D';
                    self->getDefender()->escalate(UTIL::Pair<std::uint8_t, std::vector<std::string>>(0b010, {reason + " ; " + cmd }));
                }
            }

        DWORD w = 0;
        WriteFile(h, &verdict, 1, &w, nullptr);
        FlushFileBuffers(h);
        Sleep(10);
        DisconnectNamedPipe(h);
        CloseHandle(h);
        }
    }

    void Powershell::run() {
        this->aHandle = CreateThread(nullptr, 0, AmsiPolicyServer, this, 0, nullptr);
        if (!aHandle) { delete defender; kill(); return; }
        while (!killswitch) {
            if (commands.empty()) { Sleep(500); continue; }
            std::string command = commands.back();
            commands.pop_back();
            std::string m = matchCommands(command);
            if (m.empty()) m = decode(command);
            if (m.empty()) m = command;
            defender->escalate(UTIL::Pair<std::uint8_t, std::vector<std::string>>(0b010, std::vector<std::string>{m}));
        }
    }
}