#pragma once
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <windows.h>

inline std::wstring to_wstring_utf8(const std::string& s){
    if(s.empty()) return L"";
    
    int n = MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    
    return w;
}