#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7
#endif

#include "firewall.h"
#include <unordered_map>
#include <mutex>
#include <regex>
#include <sdkddkver.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

using namespace ESCALATE;

static std::string narrow_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static bool run_cmd(const std::wstring& cmd) {
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cl = L"cmd.exe /C " + cmd;
    if (!CreateProcessW(nullptr, cl.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 1; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ec == 0;
}

static std::mutex g_mtx;
static std::unordered_map<std::string, int> g_rules;

bool Firewall::addBlock(const FlexAddress* ip) {
    if (!ip) return false;
    std::wstring wip = UTIL::to_wstring_utf8(ip->getIPstr());
    std::wstring name = L"Greathelm_" + wip;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_rules.count(ip->getIPstr())) return true;
    }
    std::wstring addOut = L"netsh advfirewall firewall add rule name=\"" + name + L"\" dir=out action=block remoteip=" + wip + L" enable=yes";
    std::wstring addIn  = L"netsh advfirewall firewall add rule name=\"" + name + L"\" dir=in action=block remoteip=" + wip + L" enable=yes";
    bool a = run_cmd(addOut);
    bool b = run_cmd(addIn);
    if (a || b) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_rules[ip->getIPstr()] = 1;
        return true;
    }
    return false;
}

bool Firewall::removeBlock(const FlexAddress* ip){
    if(!ip) return false;
    std::wstring wip = UTIL::to_wstring_utf8(ip->getIPstr());
    std::wstring name = L"Greathelm_" + wip;
    std::wstring delOut = L"netsh advfirewall firewall delete rule name=\"" + name + L"\" dir=out";
    std::wstring delIn  = L"netsh advfirewall firewall delete rule name=\"" + name + L"\" dir=in";
    bool a = run_cmd(delOut);
    bool b = run_cmd(delIn);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_rules.erase(ip->getIPstr());
    }
    return a || b;
}

FlexAddress* Firewall::dnsResolve(std::wstring url) {
    WSADATA w; if (WSAStartup(MAKEWORD(2,2), &w) != 0) return nullptr;
    addrinfoW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfoW* res = nullptr;

    if (GetAddrInfoW(url.c_str(), nullptr, &hints, &res) != 0 || !res) {
        WSACleanup();
        return nullptr;
    }

    FlexAddress* out = nullptr;

    for (addrinfoW* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            wchar_t buf[INET_ADDRSTRLEN] = {0};
            InetNtopW(AF_INET, &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr, buf, INET_ADDRSTRLEN);
            out = new FlexAddress(IPver::v4, narrow_utf8(buf));
            break;
        } else if (ai->ai_family == AF_INET6) {
            wchar_t buf[INET6_ADDRSTRLEN] = {0};
            InetNtopW(AF_INET6, &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr, buf, INET6_ADDRSTRLEN);
            out = new FlexAddress(IPver::v6, narrow_utf8(buf));
            break;
        }
    }
    FreeAddrInfoW(res);
    WSACleanup();
    return out;
}

bool Firewall::isLimited(const FlexAddress* ip) {
    return false;
}

DWORD WINAPI blockYN(LPVOID param) {
    auto* castParam = static_cast<UTIL::Pair<Firewall, FlexAddress>*>(param);

    std::string text = "Should block: " + castParam->getB().getIPstr() + "?";
    int r = MessageBoxExW(nullptr, UTIL::to_wstring_utf8(text).c_str(), L"Greathelm | Firewall", MB_YESNO | MB_ICONQUESTION, 0);

    delete castParam;

    return r == IDYES ? 1u : 0u;
}

DWORD Firewall::rateLimit(LPVOID param) {
    FlexAddress* p = reinterpret_cast<FlexAddress*>(param);

    if (!p || isLimited(p)) return 1;

    addBlock(p);
    Sleep(5000);
    removeBlock(p);

    return 0;
}

FlexAddress* Firewall::parseURL(std::wstring url) {
    const std::wregex pattern(
        LR"(^(https?)://(?:[A-Za-z0-9._~\-!$&'()*+,;=%]+@)?(\[[0-9A-Fa-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63})(?::(\d{2,5}))?(?:/[^?\s#]*)?(?:\?[^#\s]*)?(?:#\S*)?$)",
        std::regex::icase);
    std::wsmatch m;

    if (!std::regex_match(url, m, pattern)) return nullptr;
    std::wstring host = m[2].str();

    if (!host.empty() && host.front() == L'[' && host.back() == L']') host = host.substr(1, host.size() - 2);
    std::string h = narrow_utf8(host);
    IN_ADDR v4{};

    if (InetPtonA(AF_INET, h.c_str(), &v4) == 1) return new FlexAddress(IPver::v4, h);
    IN6_ADDR v6{};

    if (InetPtonA(AF_INET6, h.c_str(), &v6) == 1) return new FlexAddress(IPver::v6, h);

    return dnsResolve(host);
}

bool Firewall::escalate(const FlexAddress ip) {
    auto* abc = new UTIL::Pair<Firewall, FlexAddress>(*this, ip);
    CreateThread(nullptr, 0, blockYN, (LPVOID)abc, 0, nullptr);

    return true;
}
