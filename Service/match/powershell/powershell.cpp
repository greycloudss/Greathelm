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
        for (const auto& kv : psStrings)
            if (UTIL::to_lower(key).find(kv.first) != std::string::npos) return kv.second;
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

    struct EscPack {
        ESCALATE::Defender* def;
        std::vector<std::string> payload;
    };

    static DWORD WINAPI EscalateThunk(LPVOID pv) {
        EscPack* p = static_cast<EscPack*>(pv);
        if (p && p->def) p->def->escalate(UTIL::Pair<std::uint8_t, std::vector<std::string>>(0b010, p->payload));
        
        delete p;
        return 0;
    }

    static inline bool looks_utf16le(const std::string& s) {
        size_t n = s.size() > 32 ? 32 : s.size();
        if (n < 4) return false;

        size_t zeros = 0;

        for (size_t i = 1; i < n; i += 2)
            if (s[i] == 0) ++zeros;

        return zeros >= n / 4;
    }

    static std::string to_utf8_from_utf16le(const std::string& u16) {
        if (u16.empty()) return {};

        int wlen = (int)(u16.size() / 2);

        const wchar_t* ws = reinterpret_cast<const wchar_t*>(u16.data());

        int need8 = WideCharToMultiByte(CP_UTF8, 0, ws, wlen, nullptr, 0, nullptr, nullptr);

        if (need8 <= 0) return {};

        std::string out(need8, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws, wlen, &out[0], need8, nullptr, nullptr);

        return out;
    }

    DWORD WINAPI AmsiPolicyServer(LPVOID param) {
        MATCH::Powershell* self = static_cast<MATCH::Powershell*>(param);
        const wchar_t* pipeName = LR"(\\.\pipe\AmsiPolicy)";
        SECURITY_ATTRIBUTES sa{};
        SECURITY_DESCRIPTOR sd{};
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = &sd;
        sa.bInheritHandle = FALSE;

        for (;;) {
            HANDLE hPipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa);
            if (hPipe == INVALID_HANDLE_VALUE) {
                Sleep(200);
                continue;
            }

            if (!ConnectNamedPipe(hPipe, nullptr)) {
                DWORD e = GetLastError();
                if (e != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); continue; }
            }

            DWORD need = 0, got = 0;
            bool ok = true;
            if (!ReadFile(hPipe, &need, sizeof(need), &got, nullptr) || got != sizeof(need)) ok = false;
            const DWORD kMax = 262144;
            if (ok) { if (need == 0 || need > kMax) need = (need > kMax ? kMax : need); }

            std::string blob;
            if (ok) {
                blob.resize(need);
                DWORD off = 0;
                while (off < need) {
                    DWORD chunk = 0;
                    if (!ReadFile(hPipe, &blob[off], need - off, &chunk, nullptr) || chunk == 0) { ok = false; break; }
                    off += chunk;
                }
            }

            std::string cmdUtf8;
            if (ok) {
                if (looks_utf16le(blob)) cmdUtf8 = to_utf8_from_utf16le(blob);
                else cmdUtf8.assign(blob.data(), blob.size());
            }

            std::string norm, sNorm, reason;
            if (ok && !cmdUtf8.empty()) {
                norm = UTIL::to_lower(UTIL::stripSpaces(cmdUtf8));
                sNorm = UTIL::slashFlag(norm);
                for (const auto& kv : MATCH::Powershell::psStrings) {
                    if (norm.find(kv.first) != std::string::npos || sNorm.find(UTIL::slashFlag(kv.first)) != std::string::npos) { reason = kv.second; break; }
                }
                if (reason.empty() && self) {
                    std::string dec = self->decode(cmdUtf8);
                    if (!dec.empty()) reason = dec;
                    dec = UTIL::slashFlag(dec);
                    if (!dec.empty()) reason = dec;
                }
            }

            char verdict = reason.empty() ? 'A' : 'D';
            DWORD w = 0;
            WriteFile(hPipe, &verdict, 1, &w, nullptr);
            FlushFileBuffers(hPipe);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);

            if (!reason.empty() && self) {
                EscPack* pack = new EscPack{ self->getDefender(), {} };
                pack->payload.emplace_back(reason + " ; " + cmdUtf8);
                HANDLE th = CreateThread(nullptr, 0, EscalateThunk, pack, 0, nullptr);
                if (th) CloseHandle(th);
            }

            Sleep(1);
        }
        return 0;
    }

    void Powershell::run() {
        aHandle = CreateThread(nullptr, 0, AmsiPolicyServer, this, 0, nullptr);
        if (!aHandle) { kill(); return; }
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
