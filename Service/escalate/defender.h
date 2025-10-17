#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include "../utils/pair.h"

namespace MATCH { class Powershell; }
namespace ESCALATE { class Firewall; }
namespace ESCALATE { class Event; }

namespace ESCALATE {
    class Defender {
    public:
        Defender(std::uint8_t flag, void* powershell, void* runnable, void* kernel);
        ~Defender();

        bool escalate(const UTIL::Pair<std::uint8_t, std::vector<std::string>>& threats);
        bool escalatePS(std::vector<std::string> commands);
        bool escalateTP(std::vector<std::string> runnables);
        static std::wstring getNetworkTarget(const std::wstring& text);
        bool escalateFW(const std::vector<std::wstring>& connections);
        void run();

    private:
        std::uint8_t flags;
        MATCH::Powershell* powershell;
        ESCALATE::Event* tracer;
        ESCALATE::Firewall* fwall;
    };
}
