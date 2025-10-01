#include "runnable.h"


void MATCH::Runnable::escalate() {
    this->defender->escalate(UTIL::Pair<uint8_t, std::vector<std::string>>(0b001, suspV));
    
    
}

bool MATCH::Runnable::scanSuspicion(std::string susp) {

}

void MATCH::Runnable::run() {
    while (killswitch) {
        //fetch
    } 
}