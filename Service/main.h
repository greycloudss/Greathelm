#pragma once
#include <windows.h>
#include <strsafe.h>
#include <unknwn.h>
#include "escalate/powershell/powershell.h"
#include "escalate/defender.h"
#include "menu/menu.h"

#define SVCNAME TEXT("greathelm")
#ifdef _MSC_VER
    #pragma comment(lib, "Advapi32.lib")
#endif


extern SERVICE_STATUS gSvcStatus;
extern SERVICE_STATUS_HANDLE gSvcStatusHandle;
extern HANDLE ghSvcStopEvent;

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv);
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl);
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
VOID SvcInit(DWORD dwArgc, LPTSTR* lpszArgv);
VOID SvcReportEvent(LPCTSTR szFunction);