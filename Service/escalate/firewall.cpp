#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <regex>

#pragma comment(lib, "Wtsapi32.lib")

#include "firewall.h"

using namespace ESCALATE;

static std::string narrow_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static bool run_netsh(const std::wstring& args) {
    std::wstring app = L"C:\\Windows\\System32\\netsh.exe";
    std::wstring cl = L" " + args;
    std::vector<wchar_t> cmdline(cl.begin(), cl.end());
    cmdline.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(app.c_str(), cmdline.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW | DETACHED_PROCESS,
                             nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static std::mutex g_mtx;
static std::unordered_map<std::string, int> g_rules;

bool Firewall::addBlock(const FlexAddress* ip) {
    try {
        if (!ip) return false;
        std::wstring wip = UTIL::to_wstring_utf8(ip->getIPstr());
        UTIL::logSuspicion(std::wstring(L"FIREWALL addBlock called: ") + wip);
        std::wstring name = L"Greathelm_" + wip;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            if (g_rules.count(ip->getIPstr())) return true;
        }
        std::wstring addOut = L"advfirewall firewall add rule name=\"" + name + L"\" dir=out action=block remoteip=" + wip + L" enable=yes";
        std::wstring addIn  = L"advfirewall firewall add rule name=\""  + name + L"\" dir=in  action=block remoteip=" + wip + L" enable=yes";
        bool a = run_netsh(addOut);
        bool b = run_netsh(addIn);
        if (a || b) {
            std::lock_guard<std::mutex> lk(g_mtx);
            g_rules[ip->getIPstr()] = 1;
            return true;
        }
        return false;
    } catch (...) {
        return false;
    }
}

bool Firewall::removeBlock(const FlexAddress* ip) {
    try {
        if (!ip) return false;
        std::wstring wip = UTIL::to_wstring_utf8(ip->getIPstr());
        UTIL::logSuspicion(std::wstring(L"FIREWALL removeBlock called: ") + wip);
        std::wstring name = L"Greathelm_" + wip;
        std::wstring delOut = L"advfirewall firewall delete rule name=\"" + name + L"\" dir=out";
        std::wstring delIn  = L"advfirewall firewall delete rule name=\"" + name + L"\" dir=in";
        bool a = run_netsh(delOut);
        bool b = run_netsh(delIn);
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            g_rules.erase(ip->getIPstr());
        }
        return a || b;
    } catch (...) {
        return false;
    }
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
        }
        
        if (ai->ai_family == AF_INET6) {
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
    auto* p = static_cast<UTIL::Pair<ESCALATE::Firewall, ESCALATE::FlexAddress>*>(param);
    std::wstring text = UTIL::to_wstring_utf8(std::string("Should block: ") + p->getB().getIPstr() + "?");
    DWORD sid = WTSGetActiveConsoleSessionId();
    DWORD resp = 0;
    std::wstring title = L"Greathelm | Firewall";
    WTSSendMessageW(nullptr, sid,
                    (LPWSTR)title.c_str(), (DWORD)(title.size() * sizeof(wchar_t)),
                    (LPWSTR)text.c_str(), (DWORD)(text.size() * sizeof(wchar_t)),
                    MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND | MB_TOPMOST,
                    0, &resp, FALSE);
    delete p;
    return resp == IDYES ? 1u : 0u;
}

DWORD Firewall::rateLimit(LPVOID param) {
    try {
        FlexAddress* p = reinterpret_cast<FlexAddress*>(param);
        if (!p || isLimited(p)) return 1;
        addBlock(p);
        return 0;
    } catch (...) {
        return 1;
    }
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

bool Firewall::escalate(const FlexAddress& ip) {
    auto* addr = new FlexAddress(ip.version(), ip.getIPstr());
    auto thunk = [](LPVOID pv)->DWORD {
        try {
            auto* pairp = static_cast<UTIL::Pair<Firewall*, FlexAddress*>*>(pv);
            pairp->getA()->addBlock(pairp->getB());
            delete pairp->getB();
            delete pairp;
        } catch (...) {}
        return 0;
    };
    HANDLE h = CreateThread(nullptr, 0, thunk, new UTIL::Pair<Firewall*, FlexAddress*>(this, addr), 0, nullptr);
    if (h) CloseHandle(h);
    return true;
}
