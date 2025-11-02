#include <winsock2.h>
#include <windows.h>
#include "defender.h"
#include <memory>
#include <algorithm>
#include <regex>
#include <cwctype>
#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include "../utils/strings.h"
#include "../utils/pair.h"
#include "../match/powershell/powershell.h"
#include "firewall.h"

using namespace ESCALATE;
using namespace UTIL;

static std::wstring normalize_trim(std::wstring s) {
    while (!s.empty() && iswspace((wint_t)s.front())) s.erase(s.begin());
    while (!s.empty() && iswspace((wint_t)s.back())) s.pop_back();
    return s;
}

std::wstring Defender::getNetworkTarget(const std::wstring& text) {
    static const std::wregex pattern(
        LR"((?i)\b((([a-z0-9-]+\.)+[a-z]{2,}(:\d{1,5})?)|((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.|$)){4}(:\d{1,5})?)\b)",
        std::regex::icase);
    std::wsmatch match;
    if (std::regex_search(text, match, pattern)) return match.str();
    return L"";
}

static std::wstring extractTargetFromCommand(const std::wstring& text) {
    if (text.empty()) return L"";
    std::wstring low = text;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);

    size_t pos = low.find(L"tcpclient");
    if (pos != std::wstring::npos) {
        size_t q1 = low.find_first_of(L"\'\"", pos);
        if (q1 != std::wstring::npos) {
            wchar_t quote = low[q1];
            size_t q2 = low.find(quote, q1 + 1);
            if (q2 != std::wstring::npos && q2 > q1 + 1) {
                std::wstring candidate = text.substr(q1 + 1, q2 - q1 - 1);
                candidate = normalize_trim(candidate);
                if (!candidate.empty() && candidate.size() < 512) return candidate;
            }
        }
        size_t paren = low.find(L"(", pos);
        if (paren != std::wstring::npos) {
            size_t i = paren + 1;
            while (i < low.size() && iswspace((wint_t)low[i])) ++i;
            size_t j = i;
            while (j < low.size() && (iswalnum((wint_t)low[j]) || low[j]==L'.' || low[j]==L':' || low[j]==L'[' || low[j]==L']' || low[j]==L'-')) ++j;
            if (j > i) {
                std::wstring candidate = text.substr(i, j - i);
                candidate = normalize_trim(candidate);
                if (!candidate.empty() && candidate.size() < 512) return candidate;
            }
        }
    }

    pos = low.find(L"new-object");
    if (pos != std::wstring::npos) {
        size_t tcp = low.find(L"net.sockets.tcpclient", pos);
        if (tcp != std::wstring::npos) {
            size_t q1 = low.find_first_of(L"\'\"", tcp);
            if (q1 != std::wstring::npos) {
                wchar_t quote = low[q1];
                size_t q2 = low.find(quote, q1 + 1);
                if (q2 != std::wstring::npos && q2 > q1 + 1) {
                    std::wstring candidate = text.substr(q1 + 1, q2 - q1 - 1);
                    candidate = normalize_trim(candidate);
                    if (!candidate.empty() && candidate.size() < 512) return candidate;
                }
            }
        }
    }

    static const std::vector<std::wstring> verbs = { L"connect", L"connect-tcp", L"connect-tcplistener", L"connect-client" };
    for (const auto& v : verbs) {
        pos = low.find(v);
        if (pos != std::wstring::npos) {
            size_t q1 = low.find_first_of(L"\'\"", pos);
            if (q1 != std::wstring::npos) {
                wchar_t quote = low[q1];
                size_t q2 = low.find(quote, q1 + 1);
                if (q2 != std::wstring::npos && q2 > q1 + 1) {
                    std::wstring candidate = text.substr(q1 + 1, q2 - q1 - 1);
                    candidate = normalize_trim(candidate);
                    if (!candidate.empty() && candidate.size() < 512) return candidate;
                }
            }
            size_t i = pos + v.size();
            while (i < low.size() && (iswspace((wint_t)low[i]) || low[i]==L':' || low[i]==L'-')) ++i;
            size_t j = i;
            while (j < low.size() && (iswalnum((wint_t)low[j]) || low[j]==L'.' || low[j]==L':' || low[j]==L'[' || low[j]==L']' || low[j]==L'-')) ++j;
            if (j > i) {
                std::wstring candidate = text.substr(i, j - i);
                candidate = normalize_trim(candidate);
                if (!candidate.empty() && candidate.size() < 512) return candidate;
            }
        }
    }

    return Defender::getNetworkTarget(text);
}

static DWORD WINAPI warnThread(LPVOID param) {
    std::unique_ptr<std::wstring> p(static_cast<std::wstring*>(param));
    try {
        if (!p) return 0;
        DWORD sid = WTSGetActiveConsoleSessionId();
        if (sid == 0xFFFFFFFF) return 0;
        DWORD resp = 0;
        std::wstring title = L"Greathelm Warning";
        WTSSendMessageW(nullptr, sid,
                        (LPWSTR)title.c_str(), (DWORD)(title.size() * sizeof(wchar_t)),
                        (LPWSTR)p->c_str(), (DWORD)(p->size() * sizeof(wchar_t)),
                        MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
                        0, &resp, FALSE);
    } catch (...) {}
    return 0;
}

Defender::Defender(uint8_t flag, void* ps, void* runnable, void* kernel) {
    flags = flag;
    fwall = new ESCALATE::Firewall();
    powershell = static_cast<MATCH::Powershell*>(ps);
    tracer = nullptr;
    UTIL::logSuspicion(L"Service start");
}

bool Defender::escalatePS(std::vector<std::string> commands) {
    while (!commands.empty()) {
        std::string s = std::move(commands.back());
        commands.pop_back();
        std::wstring ws = UTIL::to_wstring_utf8(s);
        std::wstring tgt = extractTargetFromCommand(ws);
        if (!tgt.empty()) {
            tgt = normalize_trim(tgt);
            if (!tgt.empty()) {
                std::vector<std::wstring> v;
                v.push_back(std::move(tgt));

                escalateFW(v);
            }
        } else {
            std::unique_ptr<std::wstring> up(new std::wstring(std::move(ws)));
            HANDLE th = CreateThread(nullptr, 0, warnThread, up.release(), 0, nullptr);
            if (th) CloseHandle(th);
        }
    }
    return true;
}

bool Defender::escalateTP(std::vector<std::string> runnables) {
    (void)runnables;
    return true;
}

bool Defender::escalateFW(const std::vector<std::wstring>& connections) {
    if (connections.empty()) return false;
    for (const auto& con : connections) {
        UTIL::logSuspicion(L"[Firewall] candidate: " + con);
        std::string s(con.begin(), con.end());
        while (!s.empty() && (s.back() == ';' || s.back() == ',' || isspace((unsigned char)s.back()))) s.pop_back();

        std::unique_ptr<FlexAddress> add;
        try {
            add.reset(new FlexAddress(IPver::v4, s));
        } catch (...) {
            try {
                add.reset(new FlexAddress(IPver::v6, s));
            } catch (...) {
                try {
                    std::wstring ws(s.begin(), s.end());
                    FlexAddress* parsed = nullptr;
                    try {
                        parsed = fwall->parseURL(ws);
                    } catch (...) {
                        parsed = nullptr;
                    }

                    if (!parsed) {
                        UTIL::logSuspicion(L"[Firewall] parseURL failed for: " + UTIL::to_wstring_utf8(s));
                        continue;
                    }
                    add.reset(parsed);
                } catch (...) {
                    UTIL::logSuspicion(L"[Firewall] parseURL exception for: " + UTIL::to_wstring_utf8(s));
                    continue;
                }
            }
        }

        if (!add) continue;

        bool ok = false;
        try {
            ok = fwall->escalate(*add);
        } catch (...) {
            UTIL::logSuspicion(L"[Firewall] escalate threw");
            continue;
        }
        return ok;
    }
    return false;
}

void Defender::escalate(const UTIL::Pair<uint8_t, std::vector<std::string>>& threats) {
    if (threats.getA() == 0b010) {
        for (const auto& s : threats.getB()) UTIL::logSuspicion(L"[PowerShell] " + UTIL::to_wstring_utf8(s));
        escalatePS(threats.getB());
    }
}

Defender::~Defender() {
    if (powershell) {
        try {
            powershell->kill();
        } catch (...) { } 
        
        powershell = nullptr;
    }
    delete fwall;
}
