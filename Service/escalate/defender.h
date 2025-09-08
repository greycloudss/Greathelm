#pragma once
#include <windows.h>
#include "../utils/strings.h"
#include "../utils/pair.h"
#include <array>
#include <cstdint>


namespace MATCH { class Powershell; class Runnables; }
namespace KERNEL { class Kernel; }

namespace ESCALATE {
    DWORD WINAPI defThread(LPVOID* param) {
        ((Defender*)param)->run();
        return 0;
    }

    class Defender {
        private:
            uint8_t flags;
            
            // if needed add ipv4 and ipv6 support for purging

            void purgeConnection(UTIL::Pair<byte[], int> ip);

            UTIL::Pair<byte[], int> getIP(std::string);

            inline bool escalatePS(std::vector<std::string> commands); // Powershell
            inline bool escalateTP(std::vector<std::string> runnables); // Runnables
            inline bool escalateFW(std::vector<std::string> connections); // Connections

            void notifyUser(std::string threat);
            MATCH::Runnable* runnable;
            MATCH::Powershell* powershell;
            //kernel here too as ptr
        public:
            Defender(uint8_t flag, LPVOID powershell, LPVOID runnable, LPVOID kernel);

            bool escalate(const UTIL::Pair<uint8_t, std::vector<std::string>>& threats);

            void run();

            ~Defender();
    };
};