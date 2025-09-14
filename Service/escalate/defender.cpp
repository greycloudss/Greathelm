#include "defender.h"
#include "../match/powershell/powershell.h"

//#include "../match/runnable/runnable.h"

#pragma comment(lib, "wscapi.lib")

/*
    enum class Module : std::uint8_t {
        RUNNABLE   = 1u << 0,
        POWERSHELL = 1u << 1,
        KERNEL     = 1u << 4
    };
*/

static bool logSuspicion(const std::wstring& msg) {
    wchar_t base[512] = L"";
    DWORD n = GetEnvironmentVariableW(L"ProgramData", base, 512);
    if (!n || n >= 512) return false;
    std::wstring dir = std::wstring(base) + L"\\Greathelm";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\events.log";

    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t wline[2048];
    int wn = swprintf(wline, 2048, L"%04u-%02u-%02uT%02u:%02u:%02u %ls\r\n",
                      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg.c_str());
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

ESCALATE::Defender::Defender(uint8_t flag, LPVOID powershell, LPVOID runnable, LPVOID kernel) {
    flags = flag;
    //if (flag ^ 0b001 == 0b001) this->runnable = (MATCH::Runnable*)runnable;
    if (flag ^ 0b010 == 0b010) this->powershell = (MATCH::Powershell*)powershell;
    
    //if (flag ^ 0b100 == 0b100) kernel

    logSuspicion(L"Service start");

}

static DWORD WINAPI warnThread(LPVOID param) {
    std::unique_ptr<std::wstring> p(static_cast<std::wstring*>(param));
    logSuspicion(L"SHOW: " + *p);
    DWORD sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFF) { logSuspicion(L"SKIP: no session"); return 0; }
    DWORD resp = 0;
    std::wstring title = L"Greathelm Warning";
    WTSSendMessageW(nullptr, sid,
                    (LPWSTR)title.c_str(), (DWORD)(title.size() * sizeof(wchar_t)),
                    (LPWSTR)p->c_str(), (DWORD)(p->size() * sizeof(wchar_t)),
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
                    0, &resp, FALSE);
    logSuspicion(L"RESP:" + std::to_wstring(resp));
    return 0;
}


inline bool ESCALATE::Defender::escalatePS(std::vector<std::string> commands) {
    while (!commands.empty()) {
        std::string s = std::move(commands.back());
        commands.pop_back();
        std::wstring ws(s.begin(), s.end());
        HANDLE th = CreateThread(nullptr, 0, warnThread, new std::wstring(std::move(ws)), 0, nullptr);
        if (th) CloseHandle(th);
    }
    return true;
}

inline bool ESCALATE::Defender::escalateTP(std::vector<std::string> runnables) {

}

inline bool ESCALATE::Defender::escalateFW(std::vector<std::string> connections) {

}

bool ESCALATE::Defender::escalate(const UTIL::Pair<uint8_t, std::vector<std::string>>& threats) {
    if ((threats.getA() & 0b010) != 0)  return escalatePS(threats.getB());

    return false;
}


void ESCALATE::Defender::run() {
    
}

ESCALATE::Defender::~Defender() {
    if(powershell) powershell->kill();
    //if (runnable) runnable->kill();
    powershell = nullptr;
    //runnable = nullptr;
}