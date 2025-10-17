#pragma once
#include <cstdint>
#include "../utils/pair.h"
#include "../utils/strings.h"
#include <winsock2.h>
#include <ws2tcpip.h>

namespace ESCALATE {
    enum class IPver : uint8_t { v4, v6 };

    class FlexAddress {
        IPver flag{};
        uint8_t* address{};
        std::string strAddress;

        void parseIP() {
            const size_t n = flag == IPver::v4 ? 4u : 16u;
            address = static_cast<uint8_t*>(std::malloc(n));
            if (!address) throw std::bad_alloc();
            if (flag == IPver::v4) {
                IN_ADDR v4{};
                if (InetPtonA(AF_INET, strAddress.c_str(), &v4) != 1) {
                    std::free(address);
                    address=nullptr;
                    throw std::invalid_argument("invalid IPv4");
                }
                memcpy(address, &v4, 4);
            } else {
                IN6_ADDR v6{};
                if (InetPtonA(AF_INET6, strAddress.c_str(), &v6) != 1) {
                    std::free(address);
                    address=nullptr;
                    throw std::invalid_argument("invalid IPv6");
                }
                memcpy(address, &v6, 16);
            }
        }
    public:
        FlexAddress(IPver f, const std::string& addressStr) : flag(f), strAddress(addressStr) {
            parseIP();
        }

        FlexAddress() = default;

        const std::string& getIPstr() const {
            return strAddress;
        }

        IPver version() const {
            return flag;
        }

        ~FlexAddress() {
            std::free(address);
        }
    };
}