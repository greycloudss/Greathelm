#include "main.h"

// main user mode service - greathelm

SERVICE_STATUS gSvcStatus = {};
SERVICE_STATUS_HANDLE gSvcStatusHandle = NULL;
HANDLE ghSvcStopEvent = NULL;

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SERVICE_TABLE_ENTRY ste[] = { { const_cast<LPTSTR>(SVCNAME), SvcMain }, { NULL, NULL } };
    StartServiceCtrlDispatcher(ste);
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

VOID SvcInit(DWORD dwArgc, LPTSTR* lpszArgv) {
    ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ghSvcStopEvent == NULL) {
        ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }
    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(ghSvcStopEvent, INFINITE);
    if (ghSvcStopEvent) { CloseHandle(ghSvcStopEvent); ghSvcStopEvent = NULL; }
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
    HANDLE hEventSource = RegisterEventSource(NULL, SVCNAME);
    if (hEventSource) {
        TCHAR Buffer[256];
        StringCchPrintf(Buffer, 256, TEXT("%s failed with %lu"), szFunction, GetLastError());
        LPCTSTR Strings[1] = { Buffer };
        ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, 0xC0020001, NULL, 1, 0, Strings, NULL);
        DeregisterEventSource(hEventSource);
    }
}