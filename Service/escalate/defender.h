#pragma once
#include <windows.h>
#include "powershell/powershell.h"
#include "registry/registry.h"
#include "firewall.h"


namespace ESC {
    class Defender {
        private:
            Registry* registry;
            Powershell* powershell;
            Firewall* firewall;
        public:
            Defender();
            void run();
            void escalate(uint8_t ptr);
            ~Defender();
    };
};