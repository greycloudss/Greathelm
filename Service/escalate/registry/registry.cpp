#include "registry.h"
#include "../../util/strings.h"

namespace ESC {
    Registry::Registry() {
        sessionHandle = 0;
        traceHandle = 0;
        props = nullptr;
        sessionName = L"GreathelmRegistry";
        workerThread = nullptr;
        running = 0;
    }

    bool Registry::start() {
        if (running) return false;

        ULONG bufferSize  = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(wchar_t) * 256;
        props = (EVENT_TRACE_PROPERTIES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (!props) {
            UTIL::logSuspicion(L"[Registry] failed to allocate trace properties");
            return false;
        }

        props->Wnode.BufferSize = bufferSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ULONG status = StartTraceW(&sessionHandle, sessionName.c_str(), props);
        if (status == ERROR_ALREADY_EXISTS) {
            UTIL::logSuspicion(L"[Registry] existing session detected, stopping prior instance");
            StopTraceW(0, sessionName.c_str(), props);
            status = StartTraceW(&sessionHandle, sessionName.c_str(), props);
        }
        if (status != ERROR_SUCCESS) {
            UTIL::logSuspicion(L"[Registry] StartTraceW failed err=" + UTIL::to_wstring_utf8(std::to_string(status)));
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            return false;
        }

        ENABLE_TRACE_PARAMETERS enableParams = {};
        ZeroMemory(&enableParams, sizeof(enableParams));
        enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION;

        // Microsoft-Windows-Kernel-Registry provider
        GUID RegistryProviderGuid = {0x70eb4f03,0xc1de,0x4f73,{0xa0,0x51,0x33,0xd1,0x3d,0x54,0x13,0xbd}};

        status = EnableTraceEx2(sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFF, 0, 0, &enableParams);
        if (status != ERROR_SUCCESS) {
            UTIL::logSuspicion(L"[Registry] EnableTraceEx2 failed err=" + UTIL::to_wstring_utf8(std::to_string(status)));
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            return false;
        }

        EVENT_TRACE_LOGFILEW traceLog = {};
        traceLog.LoggerName = (LPWSTR)((BYTE*)props + props->LoggerNameOffset);
        traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLog.EventRecordCallback = &Registry::StaticEventRecordCallback;
        traceLog.Context = this;
        traceHandle = OpenTraceW(&traceLog);

        if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
            UTIL::logSuspicion(L"[Registry] OpenTraceW failed");
            EnableTraceEx2(sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            return false;
        }
        running = TRUE;

        workerThread = CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
        if (!workerThread) {
            UTIL::logSuspicion(L"[Registry] CreateThread failed");
            CloseTrace(traceHandle);
            traceHandle = 0;
            EnableTraceEx2(sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            running = FALSE;
            return false;
        }

        UTIL::logSuspicion(L"[Registry] ETW monitoring started");
        return true;
    }

    bool Registry::stop() {
        if (!running) return false;
        
        running = FALSE;
        if (workerThread) {
            WaitForSingleObject(workerThread, INFINITE);
            CloseHandle(workerThread);
            workerThread = nullptr;
        }

        if (traceHandle) {
            CloseTrace(traceHandle);
            traceHandle = 0;
        }

        if (sessionHandle) {
            DisableProvider();
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            sessionHandle = 0;
        }
        
        if (props) {
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
        }

        UTIL::logSuspicion(L"[Registry] ETW monitoring stopped");
        return true;
    }

    void  Registry::readKey(const wchar_t* path, const wchar_t* key) {

    }

    Registry::~Registry() {
        stop();
    }
};
