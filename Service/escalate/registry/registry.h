#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <cwctype>
#include <string>
#include <vector>
#include <algorithm>
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

                auto readStringProp = [&](PCWSTR name)->std::wstring {
                    PROPERTY_DATA_DESCRIPTOR desc{};
                    desc.PropertyName = (ULONGLONG)name;
                    desc.ArrayIndex = ULONG_MAX;
                    ULONG needed = 0;
                    if (TdhGetPropertySize(ev, 0, nullptr, 1, &desc, &needed) != ERROR_SUCCESS || needed == 0) return L"";
                    std::vector<BYTE> buf(needed);
                    if (TdhGetProperty(ev, 0, nullptr, 1, &desc, needed, buf.data()) != ERROR_SUCCESS) return L"";
                    return std::wstring(reinterpret_cast<wchar_t*>(buf.data()));
                };

                auto readUIntProp = [&](PCWSTR name)->DWORD {
                    PROPERTY_DATA_DESCRIPTOR desc{};
                    desc.PropertyName = (ULONGLONG)name;
                    desc.ArrayIndex = ULONG_MAX;
                    ULONG needed = 0;
                    if (TdhGetPropertySize(ev, 0, nullptr, 1, &desc, &needed) != ERROR_SUCCESS || needed == 0 || needed > sizeof(DWORD)) return 0;
                    DWORD val = 0;
                    if (TdhGetProperty(ev, 0, nullptr, 1, &desc, needed, (PBYTE)&val) != ERROR_SUCCESS) return 0;
                    return val;
                };

                auto eventNameFromId = [](USHORT id)->std::wstring {
                    switch (id) {
                        case 1:  return L"CreateKey";
                        case 2:  return L"OpenKey";
                        case 3:  return L"DeleteKey";
                        case 4:  return L"QueryKey";
                        case 5:  return L"SetValue";
                        case 6:  return L"DeleteValue";
                        case 7:  return L"QueryValue";
                        case 8:  return L"EnumerateKey";
                        case 9:  return L"EnumerateValue";
                        case 10: return L"CallbackBegin";
                        case 11: return L"CallbackEnd";
                        case 12: return L"SetInformation";
                        case 13: return L"Flush";
                        default: return L"Other";
                    }
                };

                auto toLower = [](std::wstring s) {
                    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)std::towlower(c); });
                    return s;
                };

                auto isInterestingEvent = [](USHORT id)->bool {
                    switch (id) {
                        case 1:  // CreateKey
                        case 3:  // DeleteKey
                        case 5:  // SetValue
                        case 6:  // DeleteValue
                        case 12: // SetInformation
                            return true;
                        default:
                            return false;
                    }
                };

                auto looksLikeIOC = [&](const std::wstring& keyPath, const std::wstring& valueName, USHORT eventId)->bool {
                    static const std::vector<std::wstring> keyPatterns = {
                        L"\\software\\microsoft\\windows\\currentversion\\run",
                        L"\\software\\microsoft\\windows\\currentversion\\runonce",
                        L"\\software\\microsoft\\windows\\currentversion\\runservices",
                        L"\\software\\microsoft\\windows\\currentversion\\runservicesonce",
                        L"\\software\\microsoft\\windows\\currentversion\\policies\\system",
                        L"\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
                        L"\\software\\microsoft\\windows nt\\currentversion\\winlogon",
                        L"\\software\\microsoft\\windows nt\\currentversion\\windows",
                        L"\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
                        L"\\software\\microsoft\\windows nt\\currentversion\\silentprocessexit",
                        L"\\microsoft\\windows\\currentversion\\startupapproved",
                        L"\\software\\wow6432node\\microsoft\\windows\\currentversion\\run",
                        L"\\software\\wow6432node\\microsoft\\windows\\currentversion\\runonce",
                        L"\\software\\wow6432node\\microsoft\\windows\\currentversion\\runservices",
                        L"\\software\\wow6432node\\microsoft\\windows\\currentversion\\runservicesonce",
                        L"\\system\\currentcontrolset\\services",
                        L"\\system\\currentcontrolset\\control\\session manager",
                        L"\\system\\currentcontrolset\\control\\terminal server",
                        L"\\system\\currentcontrolset\\control\\lsa",
                        L"\\system\\currentcontrolset\\control\\securityproviders\\wdigest"
                    };

                    static const std::vector<std::wstring> valuePatterns = {
                        L"shell", L"userinit", L"load", L"run", L"runonce",
                        L"debugger", L"command", L"autorun", L"start",
                        L"appinit_dlls", L"loadappinit_dlls", L"bootexecute",
                        L"authentication packages", L"notification packages", L"ginadll"
                    };

                    const std::wstring keyLow = toLower(keyPath);
                    const std::wstring valLow = toLower(valueName);

                    bool keyMatch = false;
                    for (const auto& pat : keyPatterns) {
                        if (!pat.empty() && keyLow.find(pat) != std::wstring::npos) { keyMatch = true; break; }
                    }

                    if (!keyMatch) return false;

                    // For value-oriented events, require the value name to match exactly to reduce false positives (e.g., "powershell").
                    if (eventId == 5 || eventId == 6 || eventId == 12) { // SetValue, DeleteValue, SetInformation
                        if (valLow.empty()) return false;
                        for (const auto& pat : valuePatterns) {
                            if (!pat.empty() && valLow == pat) return true;
                        }
                        return false;
                    }

                    return true; // key path alone is enough for create/delete/other key-centric events
                };

                std::wstring key   = readStringProp(L"KeyName");
                std::wstring value = readStringProp(L"ValueName");
                if (key.empty() && value.empty()) {
                    HeapFree(GetProcessHeap(), 0, info);
                    return;
                }

                USHORT eventId = ev->EventHeader.EventDescriptor.Id;

                // Only log registry events that look like persistence or execution IOCs.
                if (!isInterestingEvent(eventId) || !looksLikeIOC(key, value, eventId)) {
                    HeapFree(GetProcessHeap(), 0, info);
                    return;
                }

                DWORD pid = ev->EventHeader.ProcessId;
                std::wstring image = L"unknown";
                if (pid) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                    if (hProc) {
                        wchar_t buf[MAX_PATH];
                        DWORD cch = MAX_PATH;
                        if (QueryFullProcessImageNameW(hProc, 0, buf, &cch) && cch > 0) {
                            image.assign(buf, cch);
                        }
                        CloseHandle(hProc);
                    } else {
                        image = L"pid:" + std::to_wstring(pid);
                    }
                }

                DWORD statusProp = readUIntProp(L"Status");
                std::wstring msg = L"[Registry] " + eventNameFromId(eventId) +
                                   L" (id=" + std::to_wstring(eventId) + L") " +
                                   L"pid=" + std::to_wstring(pid) + L" proc=" + image +
                                   L" key=" + key + L" value=" + value;
                if (statusProp) {
                    wchar_t statusBuf[32];
                    swprintf(statusBuf, 32, L" status=0x%08X", statusProp);
                    msg += statusBuf;
                }

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

                GUID RegistryProviderGuid = {0x70eb4f03,0xc1de,0x4f73,{0xa0,0x51,0x33,0xd1,0x3d,0x54,0x13,0xbd}};

                EnableTraceEx2( sessionHandle, &RegistryProviderGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, &p);
            }
    };
};
