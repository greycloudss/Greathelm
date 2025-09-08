#pragma once
#include <windows.h>
#include "../utils/strings.h"
#include "../utils/pair.h"
#include "../modules.h"

namespace MATCH { class Powershell; class Runnables; }
namespace KERNEL { class Kernel; }

namespace ESCALATE {
    class Defender {
        private:
            const Module modules;
             
            void escalatePS(std::string* commands); // Powershell
            void escalateTP(std::string* runnables); // Runnables
            void escalateFW(std::string* connections); // Connections
        public:
            Defender(const std::string modules[], LPVOID Powershell, LPVOID Runnable, LPVOID Kernel);

            bool escalate(const UTIL::Pair<Module, std::string[]> threats);

            void runner();

            ~Defender();
    };
};