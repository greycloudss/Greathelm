#pragma once
#include <iostream>
#include <algorithm>
#include <vector>
namespace UTIL {
    inline std::string stripSpaces(std::string s) {
        s.erase(std::remove_if(s.begin(), s.end(), [](unsigned char c){ return c==' ' || c=='\t'; }),  s.end());
        return s;
    }
    
    inline std::string slashFlag(std::string s) {
        std::replace(s.begin(), s.end(), '-', '/');
        // have heard some evasion techniques are literally just replacing a '-' with a '/' for flags, sounds stupid but its something :)
        return s;
    }

    inline std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        return s;
    }
    
    inline std::string b64decode(const std::string& in) {
        static const int T[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,
            26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
        };
    
        std::string out;
        out.reserve(in.size()*3/4);
        int val = 0;
        int valb = -8;
        for (unsigned char uc : in) {
            if (uc == '=') break;
            if (std::isspace(uc)) continue;
            int d = T[uc];
            if (d < 0) continue;
            val = (val << 6) | d;
            valb += 6;
            if (valb >= 0) {
                out.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }
};