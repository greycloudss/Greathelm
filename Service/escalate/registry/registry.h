#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include "../../util/strings.h"

#pragma comment(lib, "advapi32.lib");
#pragma comment(lib, "tdh.lib");

namespace ESC {
    class Registry {
        public:
            Registry();
            bool start();
            bool stop();
            void readKey(const wchar_t* path, const wchar_t* key);
            ~Registry();

        private:
            TRACEHANDLE sessionHandle;
            TRACEHANDLE traceHandle;
            EVENT_TRACE_PROPERTIES* props;
            std::wstring sessionName;
            HANDLE workerThread;
            volatile LONG running;

            static VOID WINAPI StaticEventRecordCallback(PEVENT_RECORD ev){
                Registry* self = (Registry*)ev->UserContext;
                if (self) self->OnEvent(ev);
            }

            void OnEvent(PEVENT_RECORD ev) {
                ULONG status = 0;
                ULONG bufferSize = 0;
                status = TdhGetEventInformation(ev, 0, nullptr, nullptr, &bufferSize);
                if (status != ERROR_INSUFFICIENT_BUFFER)
                    return;

                PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
                if (!info)
                    return;

                status = TdhGetEventInformation(ev, 0, nullptr, info, &bufferSize);
                if (status != ERROR_SUCCESS) {
                    HeapFree(GetProcessHeap(), 0, info);
                    return;
                }
                std::wstring msg = L"[Registry] event id=" + std::to_wstring(ev->EventHeader.EventDescriptor.Id);
                UTIL::logSuspicion(msg);

                HeapFree(GetProcessHeap(), 0, info);
            }

            static DWORD WINAPI ThreadProc(LPVOID param) {
                Registry* self = (Registry*)param;
                if (!self)
                    return 1;

                TRACEHANDLE handles[1];
                handles[0] = self->traceHandle;

                ProcessTrace(handles, 1, nullptr, nullptr);

                return 0;
            }

            void DisableProvider() {
                ENABLE_TRACE_PARAMETERS p;
                ZeroMemory(&p, sizeof(p));
                p.Version = ENABLE_TRACE_PARAMETERS_VERSION;

                GUID RegistryProviderGuid = { 0xAE53722E, 0xC863, 0x11d2, {0x86,0x6F,0x00,0xC0,0x4F,0xB9,0x98,0xA2} };

                EnableTraceEx2( sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, &p);
            }
    };
};
