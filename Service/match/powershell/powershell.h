#pragma once
#include <windows.h>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>
#include "../../utils/strings.h"

namespace ESCALATE { class Defender; }

namespace MATCH {
    DWORD WINAPI AmsiPolicyServer(LPVOID pv);
    bool evaluate(const void* p, size_t n);

    class Powershell {
        private:
            std::vector<std::string> commands;
            ESCALATE::Defender* defender;
            volatile bool killswitch = false;
            volatile HANDLE aHandle{};
        public:
            inline static const std::unordered_map<std::string, std::string> psStrings = {
                {"-encodedcommand", "-encodedcommand"},
                {"-enc", "-enc "},
                {"-executionpolicybypass", "-executionpolicy bypass"},
                {"-executionpolicyunrestricted", "-executionpolicy unrestricted"},
                {"-noprofile", "-noprofile"},
                {"-nop", "-nop"},
                {"-noninteractive", "-noninteractive"},
                {"-windowstylehidden", "-windowstyle hidden"},
                {"-whidden", "-w hidden"},
                {"-version2", "-version 2"},
                {"powershell-e", "powershell -e "},
                {"powershell.exe-e", "powershell.exe -e"},
                {"powershell-enc", "powershell -enc"},
                {"iex", "iex "},
                {"invoke-expression", "invoke-expression"},
                {"invoke-webrequest", "invoke-webrequest"},
                {"iwr", "iwr "},
                {"curl", "curl "},
                {"wget", "wget "},
                {"start-bitstransfer", "start-bitstransfer"},
                {"new-objectnet.webclient", "new-object net.webclient"},
                {"downloadstring(", "downloadstring("},
                {"downloadfile(", "downloadfile("},
                {"[convert]::frombase64string(", "[convert]::frombase64string("},
                {"add-type", "add-type"},
                {"[system.reflection.assembly]::load", "[system.reflection.assembly]::load"},
                {"reflection.assembly]::load", "reflection.assembly]::load"},
                {"virtualalloc", "virtualalloc"},
                {"writeprocessmemory", "writeprocessmemory"},
                {"createremotethread", "createremotethread"},
                {"ntprotectvirtualmemory", "ntprotectvirtualmemory"},
                {"ntcreatesection", "ntcreatesection"},
                {"[system.runtime.interopservices.marshal]::copy", "[system.runtime.interopservices.marshal]::copy"},
                {"amsiutils", "amsiutils"},
                {"amsiinitfailed", "amsiinitfailed"},
                {"amsi.dll", "amsi.dll"},
                {"set-itemproperty", "set-itemproperty"},
                {"hklm\\software\\microsoft\\windows\\currentversion\\run", "hklm\\software\\microsoft\\windows\\currentversion\\run"},
                {"runonce", "runonce"},
                {"imagefileexecutionoptions", "image file execution options"},
                {"register-scheduledtask", "register-scheduledtask"},
                {"schtasks.exe", "schtasks.exe"},
                {"new-service", "new-service"},
                {"sc.execreate", "sc.exe create"},
                {"invoke-command-computername", "invoke-command -computername"},
                {"new-pssession", "new-pssession"},
                {"enter-pssession", "enter-pssession"},
                {"invoke-wmimethod", "invoke-wmimethod"},
                {"get-wmiobject", "get-wmiobject"},
                {"__eventfilter", "__eventfilter"},
                {"commandlineeventconsumer", "commandlineeventconsumer"},
                {"wmipermanentevent", "wmi permanent event"},
                {"bitsadmin", "bitsadmin"},
                {"mshta", "mshta"},
                {"rundll32", "rundll32"},
                {"regsvr32", "regsvr32"},
                {"comsvcs.dll", "comsvcs.dll"},
                {"wscript.shell", "wscript.shell"},
                {"netshadvfirewall", "netsh advfirewall"},
                {"vssadmindeleteshadows", "vssadmin delete shadows"},
                {"wmicshadowcopydelete", "wmic shadowcopy delete"},
                {"wevtutilcl", "wevtutil cl"},
                {"clear-eventlog", "clear-eventlog"},
                {"get-credential", "Get-Credential"},
                {"secur32.dll", "secur32.dll"},
                {"lsass", "lsass"},
                {"mimikatz", "mimikatz"},
                {"invoke-mimikatz", "invoke-mimikatz"},
                {"sekurlsa", "sekurlsa"},
                {"get-aduser", "Get-ADUser"},
                {"get-adcomputer", "Get-ADComputer"},
                {"get-addomain", "Get-ADDomain"},
                {"add-mppreference-exclusionpath", "Add-MpPreference -ExclusionPath"},
                {"set-mppreference-disablerealtimemonitoring", "Set-MpPreference -DisableRealtimeMonitoring"},
                {"token::elevate", "token::elevate"},
                {"kerberos", "kerberos"},
                {"invoke-reflectivepeinjection", "Invoke-ReflectivePEInjection"},
                {"invoke-dllinjection", "Invoke-DllInjection"},
                {"invoke-shellcode", "Invoke-Shellcode"},
                {"invoke-runas", "Invoke-RunAs"},
                {"invoke-tokenmanipulation", "Invoke-TokenManipulation"},
                {"get-networkconnection", "Get-NetworkConnection"},
                {"test-connection-computername", "Test-Connection -ComputerName"},
                {"copy-item\\\\*\\admin$", "copy-item \\\\*\\admin$"},
                {"psexec", "psexec"},
                {"sharphound", "sharpHound"},
                {"bloodhound", "bloodhound"},
                {"cobaltstrike", "CobaltStrike"},
                {"beacon", "beacon "},
                {"frombase64string(", "frombase64string("},
                {"system.net.sockets.tcpclient", "system.net.sockets.tcpclient"},
                {"system.io.compression.deflatestream", "system.io.compression.deflatestream"},
                {"certutil-decode", "certutil -decode"},
                {"certutil-urlcache", "certutil -urlcache"},
                {"expand-archive", "Expand-Archive"},
                {"invoke-webrequest-usebasicparsing", "Invoke-WebRequest -UseBasicParsing"},
                {"add-type-typedefinition", "Add-Type -TypeDefinition"},
                {"add-type-path", "Add-Type -Path"},
                {"bypass", "Bypass"},
                {"unrestricted", "Unrestricted"},
                {"hiddenwindow", "HiddenWindow"},
                {"greathelm_Provider.dll","Greathelm_Provider.dll"}, // tracking ourselves
                {"greathelm_service.exe","Greathelm_service.exe"}    // tracking ourselves
            };

            bool getKillswitch() { return killswitch; }
            void kill() { killswitch = true; }
            Powershell(ESCALATE::Defender* defender) : defender(defender) {}
            std::string decode(std::string command);
            std::string matchCommands(std::string command);
            ESCALATE::Defender* getDefender() { return defender; }
            void run();
    };

    inline DWORD WINAPI psThread(LPVOID param) {
        try {
            ((Powershell*)param)->run();
        } catch (...) {
            UTIL::logSuspicion(L"[psThread] unhandled exception");
        }
        return 0;
    }
}
