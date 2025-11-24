#include "registry.h"

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
        if (!props) return false;

        props->Wnode.BufferSize = bufferSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ULONG status = StartTraceW(&sessionHandle, sessionName.c_str(), props);
        if (status != ERROR_SUCCESS) {
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            return false;
        }

        ENABLE_TRACE_PARAMETERS enableParams = {};
        ZeroMemory(&enableParams, sizeof(enableParams));
        enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION;

        GUID RegistryProviderGuid = {0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11} };

        status = EnableTraceEx2(sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFF, 0, 0, &enableParams);
        if (status != ERROR_SUCCESS) {
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            return false;
        }

        EVENT_TRACE_LOGFILEW traceLog = {};
        traceLog.LoggerName = (LPWSTR)((BYTE*)props + props->LoggerNameOffset);
        traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLog.EventRecordCallback = &Registry::StaticEventRecordCallback;
        traceHandle = OpenTraceW(&traceLog);

        if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
            EnableTraceEx2(sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            return false;
        }
        running = TRUE;

        workerThread = CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
        if (!workerThread) {
            CloseTrace(traceHandle);
            traceHandle = 0;
            EnableTraceEx2(sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
            StopTraceW(sessionHandle, sessionName.c_str(), props);
            HeapFree(GetProcessHeap(), 0, props);
            props = nullptr;
            running = FALSE;
            return false;
        }

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
    }

    void  Registry::readKey(const wchar_t* path, const wchar_t* key) {

    }

    Registry::~Registry() {
        
    }
};