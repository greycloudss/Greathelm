#include "firewall.h"

#include "../utils/misc.h"



bool ESCALATE::Firewall::initFirewall() {


    return false;
}

ESCALATE::Firewall::Firewall() {

}

ESCALATE::Firewall::~Firewall() {

}




UTIL::Pair<const char, const byte*>* ESCALATE::Firewall::dnsResolve(std::wstring url) {
    WSADATA w; if (WSAStartup(MAKEWORD(2,2), &w) != 0) return nullptr;
    addrinfoW hints = {}; hints.ai_family = AF_UNSPEC; addrinfoW* res = nullptr;
    if (GetAddrInfoW(url.c_str(), nullptr, &hints, &res) != 0 || !res) {
        WSACleanup();
        return nullptr;
    }

    UTIL::Pair<const char, const byte*>* out = nullptr;
    for (addrinfoW* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            auto sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
            byte* b = new byte[4];
            unsigned char* p = reinterpret_cast<unsigned char*>(&sa->sin_addr.S_un.S_addr);
            b[0]=p[0]; b[1]=p[1]; b[2]=p[2]; b[3]=p[3];
            out = new UTIL::Pair<const char, const byte*>(0, b);
            break;
        } else if (ai->ai_family == AF_INET6) {
            auto sa6 = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
            byte* b = new byte[16];
            memcpy(b, sa6->sin6_addr.u.Byte, 16);
            out = new UTIL::Pair<const char, const byte*>(1, b);
            break;
        }
    }
    FreeAddrInfoW(res);
    WSACleanup();
    return out;
}


// -------------------------- whitelist and blocking --------------------------

bool ESCALATE::Firewall::checkAvailability(const std::wstring ip) {

    return false;
}

bool ESCALATE::Firewall::addBlockIPv4(const byte* ip) {

    return false;
}

bool ESCALATE::Firewall::addBlockIPv6(const byte* ip) {

    return false;
}

bool ESCALATE::Firewall::removeBlockIPv4(const byte* ip) {

    return false;
}

bool ESCALATE::Firewall::removeBlockIPv6(const byte* ip) {

    return false;
}

bool ESCALATE::Firewall::addWhitelist(std::wstring ip) {
    
    return false;
}

bool ESCALATE::Firewall::addWhitelist(std::wstring url) {


    return false;
}

INT_PTR CALLBACK DlgProc(HWND d, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_INITDIALOG) {
        const std::wstring* ip = reinterpret_cast<const std::wstring*>(l);
        std::wstring buf(256, L'\0');
        StringCchPrintfW(buf.data(), buf.size(), L"Should I rate limit: %ls ip?", ip->c_str());
        SetDlgItemTextW(d, 201, buf.c_str());
        return TRUE;
    }
    if (m == WM_COMMAND && (LOWORD(w) == IDYES || LOWORD(w) == IDNO)) {
        EndDialog(d, LOWORD(w));
        return TRUE;
    }
    return FALSE;
}

DWORD WINAPI ESCALATE::Firewall::blockYN(LPVOID param) {
    std::wstring* ip = static_cast<std::wstring*>(param);
    
    INT_PTR retVal = DialogBoxParamW(UTIL::GetInst(), MAKEINTRESOURCEW(IDD_RATE), nullptr, DlgProc, (LPARAM)ip);
   
    switch ((int)retVal) {
        case IDYES:
            return rateLimit((LPVOID)parseIP(*ip));
        case IDNO:
            return 0;
        default:
            return GetLastError();
    }
}

DWORD WINAPI ESCALATE::Firewall::rateLimit(LPVOID param) {
    //input pair to see what type of ip to block element A is the flag, element B is the ip itself
    UTIL::Pair<const char, const byte*>* abc = (UTIL::Pair<const char, const byte*>*) param;
    if (abc->getA() == 0) {
        addBlockIPv4(abc->getB());
        Sleep(5000);
        removeBlockIPv4(abc->getB());
    } else {
        addBlockIPv6(abc->getB());
        Sleep(5000);
        removeBlockIPv6(abc->getB());
    }
    return 0;
}

UTIL::Pair<char, byte*>* ESCALATE::Firewall::parseIPv6(std::wstring ip) {
    std::vector<std::wstring> tokens;
    tokens.reserve(9);
    size_t start = 0;
    for (size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == L':') {
            tokens.emplace_back(ip.substr(start, i - start));
            start = i + 1;
        }
    }

    int dbl = -1;
    std::vector<uint16_t> parts;
    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::wstring& t = tokens[i];
        if (t.empty()) {
            if (dbl == -1) dbl = (int)parts.size();
            continue;
        }
        if (t.find(L'.') != std::wstring::npos) {
            byte v4[4];
            if (!UTIL::ParseIPv4Octets(t, v4)) return nullptr;
            parts.push_back((uint16_t(v4[0]) << 8) | v4[1]);
            parts.push_back((uint16_t(v4[2]) << 8) | v4[3]);
        } else {
            uint16_t v = 0;
            if (!UTIL::ParseHex16(t, v)) return nullptr;
            parts.push_back(v);
        }
    }

    if (dbl >= 0) {
        int missing = 8 - (int)parts.size();
        if (missing < 0) return nullptr;
        parts.insert(parts.begin() + dbl, missing, 0);
    }
    if (parts.size() != 8) return nullptr;

    byte* out = new byte[16];
    for (int i = 0; i < 8; ++i) {
        out[i * 2 + 0] = static_cast<byte>((parts[i] >> 8) & 0xFF);
        out[i * 2 + 1] = static_cast<byte>(parts[i] & 0xFF);
    }
    return new UTIL::Pair<char, byte*>(1, out);
}

UTIL::Pair<char, byte*>* ESCALATE::Firewall::parseIPv4(std::wstring ip) {
    byte* out = new byte[4];
    if (!UTIL::ParseIPv4Octets(ip, out)) { delete[] out; return nullptr; }
    return new UTIL::Pair<char, byte*>(0, out);
}

std::wstring ESCALATE::Firewall::formatIP(UTIL::Pair<const char, const byte*>* ip) {

    return {};
}
/*
    std::wstring Defender::getNetworkTarget(const std::wstring& text) {
        static const std::wregex pattern(
            LR"((?i)\b((([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d{1,5})?)|((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.|$)){4}(:\d{1,5})?)\b)",
            std::regex::icase);
        std::wsmatch match;
        if (std::regex_search(text, match, pattern))
            return match.str();
        return L"";
    }

*/
byte* ESCALATE::Firewall::parseURL(std::wstring url) {
    const std::wregex pattern(
    LR"(^(https?)://(?:[A-Za-z0-9._~\-!$&'()*+,;=%]+@)?(\[[0-9A-Fa-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63})(?::(\d{2,5}))?(?:/[^?\s#]*)?(?:\?[^#\s]*)?(?:#\S*)?$)",
    std::regex::icase);
    
    std::wstring str;

    std::wsmatch m;
    if (std::regex_match(url, m, pattern)) str = m[2].str();
    else return nullptr;

    parseIP(str);
}

// -------------------------- wrapper -------------------------- 

UTIL::Pair<char, byte*>* ESCALATE::Firewall::parseIP(std::wstring ip) {
    // the moment i realised the weakness of my flesh
    return ([&]{ for (wchar_t a : ip) if (a == L'.') return true; return false; }()) ? parseIPv4(ip) : parseIPv6(ip);
}

bool ESCALATE::Firewall::escalate(UTIL::Pair<char, byte*>* ipxflag) {

    return false;
}
