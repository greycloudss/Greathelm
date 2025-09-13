#include "defender.h"
#include "../match/powershell/powershell.h"
#include "../match/runnable/runnable.h"

#pragma comment(lib, "wscapi.lib")

/*
    enum class Module : std::uint8_t {
        RUNNABLE   = 1u << 0,
        POWERSHELL = 1u << 1,
        KERNEL     = 1u << 4
    };
*/

ESCALATE::Defender::Defender(uint8_t flag, LPVOID powershell, LPVOID runnable, LPVOID kernel) {
    flags = flag;
    if (flag ^ 0b001 == 0b001) this->runnable = (MATCH::Runnable*)runnable;
    if (flag ^ 0b010 == 0b010) this->powershell = (MATCH::Powershell*)powershell;

    //if (flag ^ 0b100 == 0b100) kernel

}

inline bool ESCALATE::Defender::escalatePS(std::vector<std::string> commands) {

}

inline bool ESCALATE::Defender::escalateTP(std::vector<std::string> runnables) {

}

inline bool ESCALATE::Defender::escalateFW(std::vector<std::string> connections) {

}

bool ESCALATE::Defender::escalate(const UTIL::Pair<uint8_t, std::vector<std::string>>& threats) {

}

void ESCALATE::Defender::run() {
    
}

ESCALATE::Defender::~Defender() {
    if(powershell) powershell->kill();
    if (runnable) runnable->kill();
    powershell = nullptr;
    runnable = nullptr;
}