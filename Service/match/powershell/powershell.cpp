#include "powershell.h"
#include "../../escalate/defender.h"
#include "../../utils/pair.h"

/***********************************************\
*   Suspicious substring in powershell commands *
*   remove all spaces in powershell then ctrl f *
*     that way can just search for substring    *
\***********************************************/

namespace MATCH {
    std::string Powershell::decode(std::string command) {
        return matchCommands(UTIL::b64decode(command));
    }
    
    std::string Powershell::matchCommands(std::string command) {
        auto key = UTIL::stripSpaces(command);
        auto it = psStrings.find(key);
        return it != psStrings.end() ? it->second : "";
    }


    void Powershell::run() {
        while (!killswitch) {
            if (commands.empty()) {
                Sleep(500);
                continue;
            }

            std::string command = commands.back();
            commands.pop_back();

            std::string m = matchCommands(command);

            if (m.empty()) m = decode(command);

            if (!m.empty()) defender->escalate(UTIL::Pair<uint8_t, std::vector<std::string>>(0b010, std::vector<std::string>{m}));
        }
    }
};