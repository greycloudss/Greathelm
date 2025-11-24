#include "powershell.h"


#include "powershell.h"
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <cstdint>

namespace ESC {
    bool Powershell::looks_utf16le(const uint8_t* data, size_t len) {
        if (!data || len < 2) return false;
        size_t pairs = len / 2;
        
        if (pairs == 0) return false;
        size_t zeros = 0;

        for (size_t i = 1; i + 1 <= len; i += 2)
            if (data[i] == 0) ++zeros;
        
        return zeros * 4 >= pairs * 3;
    }

    std::string Powershell::utf16le_to_utf8(const uint8_t* data, size_t len) {
        if (!data || len < 2 || (len % 2) != 0) return std::string();
        const wchar_t* w = reinterpret_cast<const wchar_t*>(data);
        
        int wchar_count = (int)(len / 2);
        int needed = WideCharToMultiByte(CP_UTF8, 0, w, wchar_count, nullptr, 0, nullptr, nullptr);

        if (needed <= 0) return std::string();

        std::string out;
        out.resize(needed);
        WideCharToMultiByte(CP_UTF8, 0, w, wchar_count, &out[0], needed, nullptr, nullptr);

        return out;
    }

    std::string Powershell::bytes_to_text(const uint8_t* data, size_t len) {
        if (!data || len == 0) return std::string();

        if (looks_utf16le(data, len)) {
            std::string u8 = utf16le_to_utf8(data, len);

            if (!u8.empty()) return u8;
        }

        return std::string(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data) + len);
    }

    std::string Powershell::ascii_lower(const std::string& s) {
        std::string out;
        out.resize(s.size());

        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c >= 'A' && c <= 'Z') out[i] = static_cast<char>(c - 'A' + 'a');

            else out[i] = s[i];
        }

        return out;
    }

    std::string Powershell::strip_spaces(const std::string& s) {
        std::string out;
        out.reserve(s.size());

        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (!std::isspace(c)) out.push_back(s[i]);
        }

        return out;
    }

    bool Powershell::contains_ps_keyword(const std::string& text) {
        if (text.empty()) return false;

        std::string norm = ascii_lower(text);
        std::string norm_nospace = strip_spaces(norm);

        for (const auto& kv : ESC::Powershell::psStrings) {
            const std::string& key = kv.first;
            if (key.empty()) continue;
            std::string key_norm = ascii_lower(key);

            if (norm.find(key_norm) != std::string::npos) return true;
            std::string key_norm_nospace = strip_spaces(key_norm);

            if (!key_norm_nospace.empty() && norm_nospace.find(key_norm_nospace) != std::string::npos) return true;
        }
        return false;
    }
};