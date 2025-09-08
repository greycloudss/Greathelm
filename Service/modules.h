#pragma once
#include <cstdint>

namespace MODULES {
    enum class Module : std::uint8_t {
        RUNNABLE   = 1u << 0,
        POWERSHELL = 1u << 1,
        KERNEL     = 1u << 2
    };

    using ModuleMask = std::uint8_t;
    
    constexpr ModuleMask ALL3 = static_cast<ModuleMask>(RUNNABLE) | static_cast<ModuleMask>(POWERSHELL) | static_cast<ModuleMask>(KERNEL);

    constexpr ModuleMask normalize3(ModuleMask m) {
        return (m & ALL3) ? ALL3 : 0;
    }
}
