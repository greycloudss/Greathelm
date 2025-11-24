#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "powershell/powershell.h"
#include "registry/registry.h"
#include "firewall.h"


namespace ESC {
    class Defender {
        private:
            Registry* registry;
            Powershell* powershell;
            Firewall* firewall;
            void handleTargets(const std::vector<std::string>& targets);
            void blockForDuration(const FlexAddress& ip, DWORD durationMs);
        public:
            Defender();
            void run();
            void escalate(const std::string& command);
            ~Defender();
    };
};
