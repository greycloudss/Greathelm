#pragma once

#if defined(UNICODE) && !defined(_UNICODE)
    #define _UNICODE
#elif defined(_UNICODE) && !defined(UNICODE)
    #define UNICODE
#endif

#define IDD_RATE 200
#define IDC_PROMPT 201

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


#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ESCALATE { class Defender; }

namespace ESCALATE {
    class Firewall {
        private:
            UTIL::Pair<char, byte*>* parseIPv6(std::wstring ip);
            UTIL::Pair<char, byte*>* parseIPv4(std::wstring ip);

            bool initFirewall();

            std::vector<HANDLE> limitedAdd;


            // rate limit with threads
        public:
            Firewall();
            ~Firewall();    

            bool addBlockIPv4(const byte* ip);
            bool addBlockIPv6(const byte* ip);
            bool removeBlockIPv4(const byte* ip);
            bool removeBlockIPv6(const byte* ip);

            UTIL::Pair<const char, const byte*>* dnsResolve(std::wstring url);
            bool checkAvailability(std::wstring ip);
            bool addWhitelist(std::wstring ip);
            bool addWhitelist(std::wstring url);

            DWORD WINAPI blockYN(LPVOID param);
            DWORD WINAPI rateLimit(LPVOID param);

            std::wstring formatIP(UTIL::Pair<const char, const byte*>* ip);

            byte* parseURL(std::wstring url);
            UTIL::Pair<char, byte*>* parseIP(std::wstring ip);
            
            bool escalate(UTIL::Pair<char, byte*>* ipxflag);

    };
};