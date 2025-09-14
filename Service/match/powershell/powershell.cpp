#include "powershell.h"
#include "../../escalate/defender.h"

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
        std::string key = UTIL::stripSpaces(command);
        std::unordered_map<std::string, std::string>::const_iterator it = psStrings.find(key);
        
        if (it != psStrings.end())
            return it->second;
        
        key = UTIL::slashFlag(key);
        it = psStrings.find(key);

        return it != psStrings.end() ? it->second : "";
    }


    void Powershell::run() {
        this->aHandle = CreateThread(nullptr, 0, AmsiPolicyServer, nullptr, 0, nullptr);

        if (!aHandle) {
            delete defender;
            kill();
            return;
        }

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