#include "defender.h"
#include <memory>
#include <windows.h>
#include <wtsapi32.h>
#include <regex>

#include <fwpmu.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

#include "../utils/strings.h"
#include "../match/powershell/powershell.h"

#include "event.h"
#include "firewall.h"

#ifdef _MSC_VER
    #pragma comment(lib, "wscapi.lib")
#endif

namespace ESCALATE {
    std::wstring Defender::getNetworkTarget(const std::wstring& text) {
        static const std::wregex pattern(
            LR"((?i)\b((([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d{1,5})?)|((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.|$)){4}(:\d{1,5})?)\b)",
            std::regex::icase);
        std::wsmatch match;
        if (std::regex_search(text, match, pattern))
            return match.str();
        return L"";
    }


    DWORD WINAPI warnThread(LPVOID param) {
        std::unique_ptr<std::wstring> p(static_cast<std::wstring*>(param));
        UTIL::logSuspicion(L"SHOW: " + *p);
        DWORD sid = WTSGetActiveConsoleSessionId();
        if (sid == 0xFFFFFFFF) return 0;
        DWORD resp = 0;
        std::wstring title = L"Greathelm Warning";
        WTSSendMessageW(nullptr, sid,
                        (LPWSTR)title.c_str(), (DWORD)(title.size() * sizeof(wchar_t)),
                        (LPWSTR)p->c_str(),
                        (DWORD)(p->size() * sizeof(wchar_t)),
                        MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
                        0, &resp, FALSE);
        UTIL::logSuspicion(L"RESP:" + std::to_wstring(resp));
        return 0;
    }

    Defender::Defender(uint8_t flag, LPVOID ps, LPVOID runnable, LPVOID kernel) {
        flags = flag;
        fwall = new ESCALATE::Firewall();
        powershell = static_cast<MATCH::Powershell*>(ps);
        UTIL::logSuspicion(L"Service start");
    }

    bool ESCALATE::Defender::escalatePS(std::vector<std::string> commands) {
        while (!commands.empty()) {
            std::string s = std::move(commands.back());
            commands.pop_back();
            std::wstring ws = UTIL::to_wstring_utf8(s);

            std::wstring target = getNetworkTarget(ws);
            if (!target.empty()) {
                std::vector<std::wstring>* wsVec = new std::vector<std::wstring>();
                wsVec->push_back(std::move(target));
                escalateFW(wsVec);
            }

            HANDLE th = CreateThread(nullptr, 0, warnThread, new std::wstring(std::move(ws)), 0, nullptr);
            if (th) CloseHandle(th);
        }
        return true;
    }

    bool Defender::escalateTP(std::vector<std::string> runnables) {
        return true;
    }

    bool ESCALATE::Defender::escalateFW(std::vector<std::wstring>* connections) {
        for (const std::wstring con : *connections) {
            UTIL::logSuspicion(L"[Firewall] " + con);
            FlexAddress* add = nullptr;
            std::string str(con.begin(), con.end());
            try {
                add = new FlexAddress(IPver::v4, str);
            } catch (...) {
                try {
                    add = new FlexAddress(IPver::v6, str);
                } catch (...) {
                    continue;
                }
            }
            bool retVal = fwall->escalate(*add);
            delete add;
            return retVal;
        }
        return false;
    }

    bool ESCALATE::Defender::escalate(const UTIL::Pair<uint8_t, std::vector<std::string>>& threats) {
        if (threats.getA() == 0b010) {
            for (const auto& s : threats.getB())
                UTIL::logSuspicion(L"[PowerShell] " + UTIL::to_wstring_utf8(s));
            return escalatePS(threats.getB());
        }
        return false;
    }

    Defender::~Defender() {
        delete fwall;
        
        if (powershell)  {
            powershell->kill();
            powershell = nullptr;
        }
    }
}
