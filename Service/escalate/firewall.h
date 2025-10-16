#pragma once

#if defined(UNICODE) && !defined(_UNICODE)
    #define _UNICODE
#elif defined(_UNICODE) && !defined(UNICODE)
    #define UNICODE
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7
#endif
#include <sdkddkver.h>
#include <fwptypes.h>

#include <memory>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>
#include <wtsapi32.h>
#include <regex>
#include <strsafe.h>
#include <string>

#include "../utils/pair.h"
#include "../utils/strings.h"
#include "ip.h"


#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ESCALATE { class Defender; }

namespace ESCALATE {
    class Firewall {
        public:
            bool addBlock(const FlexAddress* ip);
            bool removeBlock(const FlexAddress* ip);

            FlexAddress* dnsResolve(std::wstring url);
            bool isLimited(const FlexAddress* ip);

            DWORD rateLimit(LPVOID param);

            FlexAddress* parseURL(std::wstring url);
            
            bool escalate(const FlexAddress ip);
    };
};