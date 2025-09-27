#include "defender.h"
#include <memory>
#include <windows.h>
#include <wtsapi32.h>
#include "../utils/strings.h"
#include "../match/powershell/powershell.h"

#ifdef _MSC_VER
#pragma comment(lib, "wscapi.lib")
#endif

static bool logSuspicion(const std::wstring& msg) {
    wchar_t base[512] = L"";
    DWORD n = GetEnvironmentVariableW(L"ProgramData", base, 512);
    if (!n || n >= 512) return false;
    std::wstring dir = std::wstring(base) + L"\\Greathelm";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\events.log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t wline[2048];
    int wn = swprintf(wline, 2048, L"%04u-%02u-%02uT%02u:%02u:%02u %ls\r\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg.c_str());
    if (wn <= 0) { CloseHandle(h); return false; }
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wline, wn, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) { CloseHandle(h); return false; }
    std::string utf8; utf8.resize(bytes);
    WideCharToMultiByte(CP_UTF8, 0, wline, wn, utf8.data(), bytes, nullptr, nullptr);
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == (DWORD)utf8.size();
}

namespace ESCALATE {
    DWORD WINAPI warnThread(LPVOID param) {
        std::unique_ptr<std::wstring> p(static_cast<std::wstring*>(param));
        logSuspicion(L"SHOW: " + *p);
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
        logSuspicion(L"RESP:" + std::to_wstring(resp));
        return 0;
    }

    Defender::Defender(uint8_t flag, LPVOID ps, LPVOID runnable, LPVOID kernel) {
        flags = flag;
        powershell = static_cast<MATCH::Powershell*>(ps);
        logSuspicion(L"Service start");
    }

    bool Defender::escalatePS(std::vector<std::string> commands) {
        while (!commands.empty()) {
            std::string s = std::move(commands.back());
            commands.pop_back();
            std::wstring ws = UTIL::to_wstring_utf8(s);
            HANDLE th = CreateThread(nullptr, 0, warnThread, new std::wstring(std::move(ws)), 0, nullptr);
            if (th) CloseHandle(th);
        }
        return true;
    }

    bool Defender::escalateTP(std::vector<std::string>) { return true; }
    bool Defender::escalateFW(std::vector<std::string>) { return true; }

    bool ESCALATE::Defender::escalate(const UTIL::Pair<uint8_t, std::vector<std::string>>& threats) {
        for (const auto& s : threats.getB())
            logSuspicion(L"[PowerShell] " + UTIL::to_wstring_utf8(s));
        return escalatePS(threats.getB());
    }


    void Defender::run() {}

    Defender::~Defender() {
        if (powershell)  {
            powershell->kill();
            powershell = nullptr;
        }
    }
}
