#pragma once

#include <windows.h>
#include "../util/strings.h"
#include "resource.h"

class Menu {
    public:
        Menu();
        ~Menu();
        int run();  // pump messages until the dialog closes

    private:
        HWND hwnd{};
        static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
};


inline DWORD WINAPI MenuThread(LPVOID param) {
    try {
        Menu* menu = new Menu();
        Sleep(150000);
        delete menu;
    } catch (...) {
        UTIL::logSuspicion(L"[MenuThread] unhandled exception");
    }
    return 0;
}
