#include "main.h"
#include <unknwn.h>
#include <shellapi.h>
#include <wtsapi32.h>
#include <string>
#include <new>

SERVICE_STATUS gSvcStatus = {};
SERVICE_STATUS_HANDLE gSvcStatusHandle = nullptr;
HANDLE ghSvcStopEvent = nullptr;
static ESC::Defender* gDefender = nullptr;

static const CLSID CLSID_MyProvider = {0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11}};

static bool Greathelm_SilentLoad() {
    bool ok = false;
    HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IUnknown* u = nullptr;
    HRESULT cr = CoCreateInstance(CLSID_MyProvider, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown, (void**)&u);
    if (SUCCEEDED(cr) && u) { u->Release(); ok = true; }
    if (co == S_OK || co == S_FALSE) CoUninitialize();
    return ok;
}

static bool IsUiMode() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool uiMode = false;
    if (argv) {
        for (int i = 0; i < argc; ++i) {
            if (lstrcmpiW(argv[i], L"--ui") == 0) {
                uiMode = true;
                break;
            }
        }
        LocalFree(argv);
    }
    return uiMode;
}

static int RunMenuUi() {
    Menu menu;
    menu.run();
    return 0;
}

static bool LaunchMenuInUserSession() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) return false;

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken)) return false;

    HANDLE primaryToken = nullptr;
    bool duplicated = DuplicateTokenEx(
        userToken,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &primaryToken);

    if (!duplicated) {
        CloseHandle(userToken);
        return false;
    }

    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        CloseHandle(primaryToken);
        CloseHandle(userToken);
        return false;
    }

    std::wstring cmdLine = L"\"";
    cmdLine += exePath;
    cmdLine += L"\" --ui";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
    PROCESS_INFORMATION pi{};

    BOOL created = CreateProcessAsUserW(primaryToken, nullptr, cmdLine.data(), nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi);

    if (created) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    CloseHandle(primaryToken);
    CloseHandle(userToken);
    return created == TRUE;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (IsUiMode()) return RunMenuUi();

    const SERVICE_TABLE_ENTRYW ste[] = {
        { const_cast<LPWSTR>(SVCNAME), SvcMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(ste);
    return 0;
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    gSvcStatusHandle = RegisterServiceCtrlHandler(SVCNAME, SvcCtrlHandler);
    
    if (!gSvcStatusHandle) {
        SvcReportEvent(TEXT("RegisterServiceCtrlHandler"));
        return;
    }

    ZeroMemory(&gSvcStatus, sizeof(gSvcStatus));
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwServiceSpecificExitCode = 0;

    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    SvcInit(dwArgc, lpszArgv);
}

VOID SvcInit(DWORD, LPTSTR*) {
    ghSvcStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!ghSvcStopEvent) {
        ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    Greathelm_SilentLoad();

    gDefender = new (std::nothrow) ESC::Defender();
    if (gDefender) gDefender->run();

    LaunchMenuInUserSession();

    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(ghSvcStopEvent, INFINITE);

    if (ghSvcStopEvent) {
        CloseHandle(ghSvcStopEvent);
        ghSvcStopEvent = nullptr;
    }

    if (gDefender) {
        delete gDefender;
        gDefender = nullptr;
    }

    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}


VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    DWORD dwCheckPoint = 1;
    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;
    gSvcStatus.dwControlsAccepted = (dwCurrentState == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    gSvcStatus.dwCheckPoint = (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED) ? 0 : dwCheckPoint++;
    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

VOID WINAPI SvcCtrlHandler(DWORD dwCtrl) {
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        if (ghSvcStopEvent) SetEvent(ghSvcStopEvent);
        return;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }
}

VOID SvcReportEvent(LPCTSTR szFunction) {
    HANDLE hEventSource = RegisterEventSource(nullptr, SVCNAME);
    if (hEventSource) {
        TCHAR Buffer[256];
        StringCchPrintf(Buffer, 256, TEXT("%s failed with %lu"), szFunction, GetLastError());
        LPCTSTR Strings[1] = { Buffer };
        ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, 0xC0020001, nullptr, 1, 0, Strings, nullptr);
        DeregisterEventSource(hEventSource);
    }
}
