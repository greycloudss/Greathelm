#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

namespace UTIL {
    inline HINSTANCE GetInst() {
        return reinterpret_cast<HINSTANCE>(GetModuleHandleW(nullptr));
    }

    static bool ParseHex16(const std::wstring& s, uint16_t& out) {
        if (s.empty() || s.size() > 4) return false;
        uint32_t v = 0;
        for (wchar_t c : s) {
            v <<= 4;
            if (c >= L'0' && c <= L'9') v |= (c - L'0');
            else if (c >= L'a' && c <= L'f') v |= (c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') v |= (c - L'A' + 10);
            else return false;
        }
        out = static_cast<uint16_t>(v);
        return true;
    }

    static bool ParseIPv4Octets(const std::wstring& s, byte out[4]) {
        int part = 0;
        int acc = -1;
        for (size_t i = 0; i <= s.size(); ++i) {
            if (i == s.size() || s[i] == L'.') {
                if (acc < 0 || acc > 255 || part > 3) return false;
                out[part++] = static_cast<byte>(acc);
                acc = -1;
            } else if (s[i] >= L'0' && s[i] <= L'9') {
                if (acc < 0) acc = 0;
                acc = acc * 10 + int(s[i] - L'0');
                if (acc > 255) return false;
            } else return false;
        }
        return part == 4;
    }
}