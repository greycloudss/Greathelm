#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>

#pragma comment(lib, "advapi32.lib");
#pragma comment(lib, "tdh.lib");

namespace ESC {
    class Registry {
        private:
            TRACEHANDLE hTrace;
        public:
            Registry();
            TRACEHANDLE createTraceSession(const char* sessionName, const char* logFilePath);
            void readKey(const char* path, const char* key);
            ~Registry();
    };
};