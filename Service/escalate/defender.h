#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include "../utils/pair.h"

namespace MATCH { struct Powershell; }

namespace ESCALATE {
    class Defender {
    private:
        std::uint8_t flags;
        MATCH::Powershell* powershell;

        bool escalatePS(std::vector<std::string> commands);
        bool escalateTP(std::vector<std::string> runnables);
        bool escalateFW(std::vector<std::string> connections);
    public:
        Defender(std::uint8_t flag, LPVOID powershell, LPVOID runnable, LPVOID kernel);
        ~Defender();
        bool escalate(const UTIL::Pair<std::uint8_t, std::vector<std::string>>& threats);

        void run();
    };
}
