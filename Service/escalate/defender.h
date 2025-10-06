#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include "../utils/pair.h"

namespace ESCALATE { class Event; }
namespace ESCALATE { class Firewall; }
namespace MATCH { class Powershell; }


namespace ESCALATE {
    class Defender {
        private:
            std::uint8_t flags;
            MATCH::Powershell* powershell;

            Event* tracer;
            Firewall* fwall;
        public:
            Defender(std::uint8_t flag, LPVOID powershell, LPVOID runnable, LPVOID kernel);
            ~Defender();

            bool escalate(const UTIL::Pair<std::uint8_t, std::vector<std::string>>& threats);
            bool escalatePS(std::vector<std::string> commands);
            bool escalateTP(std::vector<std::string> runnables);
            std::wstring getNetworkTarget(const std::wstring& text);
            
            bool escalateFW(std::vector<std::wstring>* connections);
            
            void run();
    };
}
