#pragma once
#include "../../utils/strings.h"
#include "../../escalate/defender.h"
#include <windows.h>

namespace MATCH {
    class Runnables {
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

            const ESCALATE::Defender* defender;
        public:
            Runnables(const ESCALATE::Defender* defender);
            void escalate();
            bool scanSuspicion(std::string susp);

            
    };
};