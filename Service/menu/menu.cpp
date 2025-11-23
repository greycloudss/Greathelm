#include "menu.h"

Menu::Menu() : hwnd(nullptr) {
    HINSTANCE hInst = GetModuleHandle(nullptr);

    hwnd = CreateDialogParam(
        hInst,
        MAKEINTRESOURCE(IDD_MAINWINDOW),
        nullptr,
        Menu::DialogProc,
        reinterpret_cast<LPARAM>(this));

    if (hwnd) {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
    } else MessageBox(nullptr, TEXT("Greathelm successfully initialised"), TEXT("Greathelm"), MB_OK | MB_ICONINFORMATION);
}

Menu::~Menu() {
    if (hwnd && IsWindow(hwnd)) {
        DestroyWindow(hwnd);
        hwnd = nullptr;
    }
}

int Menu::run() {
    if (!hwnd) return -1;

    MSG msg{};
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (!IsWindow(hwnd)) break;
    }
    return 0;
}

INT_PTR CALLBACK Menu::DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtr(hDlg, GWLP_USERDATA, lParam);
            HINSTANCE hInst = GetModuleHandle(nullptr);
            if (HICON hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_TINY_ICON))) {
                SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
            SetTimer(hDlg, 1, 15000, nullptr); // close after 15 seconds
            return TRUE;
        }
        
        case WM_TIMER:
            if (wParam == 1) {
                KillTimer(hDlg, 1);
                DestroyWindow(hDlg);
                return TRUE;
            }
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDCANCEL) {
                DestroyWindow(hDlg);
                return TRUE;
            }
            break;

        case WM_CLOSE:
            DestroyWindow(hDlg);
            return TRUE;

        case WM_NCDESTROY: {
            auto* self = reinterpret_cast<Menu*>(GetWindowLongPtr(hDlg, GWLP_USERDATA));
            if (self) self->hwnd = nullptr;
            break;
        }
    }
    return FALSE;
}
