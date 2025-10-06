#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include "defender.h"
#include "../utils/strings.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "evntrace.lib")
#pragma comment(lib, "tdh.lib")

namespace ESCALATE {
    class Event {
        private:
            std::vector<std::wstring> names;
            const wchar_t* sessionName;
            BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096] = {};
            EVENT_TRACE_PROPERTIES_V2* properties;
            
            bool init() {
                properties = reinterpret_cast<EVENT_TRACE_PROPERTIES_V2*>(buffer);   
                sessionName = KERNEL_LOGGER_NAMEW; 
            }
        public:
            
    };
};