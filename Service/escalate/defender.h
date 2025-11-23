#pragma once
#include <windows.h>
#include "powershell/powershell.h"
#include "registry/registry.h"


namespace ESC {
    class Defender {
        private:

        public:
            Defender(Powershell *ps, Registry *reg);
            void run();
            void escalate(uint8_t ptr);
            ~Defender();
    };
};