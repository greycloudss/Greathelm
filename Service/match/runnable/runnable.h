#pragma once
#include "../../utils/strings.h"
#include "../../escalate/defender.h"

#include <windows.h>

namespace MATCH {
    DWORD WINAPI rnThread(LPVOID* param) {
        ((Runnable*)param)->run();
        return 0;
    }

    class Runnable {
        private:
            inline static const char* vitalProcessesS[] = {
                "smss.exe",
                "csrss.exe",
                "wininit.exe",
                "services.exe",
                "lsass.exe",
                "winlogon.exe",
                "svchost.exe"
            };

            inline static const char* vitalServicesS[] = {
                "RpcSs", "DcomLaunch", "RpcEptMapper", "EventLog", "PlugPlay", "Power", "SamSs", "Schedule", "Winmgmt", "LanmanServer",
                "LanmanWorkstation", "Dhcp", "Dnscache", "NlaSvc", "BFE", "MpsSvc", "CryptSvc", "EFS", "W32Time", "wuauserv", "wscsvc",
                "WinDefend", "SecurityHealthService", "Sense", "ShellHWDetection", "sppsvc", "VaultSvc", "TermService", "SessionEnv",
                "ssh-agent","SstpSvc","SysMain","vds","MDCoreSvc","LocalKdc","wlidsvc","WwanSvc","WlanSvc", "vmicguestinterface",
                "vmicheartbeat","vmickvpexchange","vmicrdv","vmicshutdown","vmictimesync","vmicvmsession","vmicvss"
            };

            ESCALATE::Defender* defender;
            volatile bool killswitch = false;

        public:
            volatile bool getKillswitch() {
                return killswitch;
            }

            void kill() { killswitch = true; }

            Runnable(ESCALATE::Defender* defender) : defender(defender) {run();};
            void escalate();
            bool scanSuspicion(std::string susp);

            void run();
    };
};