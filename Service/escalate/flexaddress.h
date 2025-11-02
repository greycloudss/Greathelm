#pragma once
#include <cstdint>
#include <string>
#include <memory>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace ESCALATE {
    enum class IPver : uint8_t { v4, v6 };

    class FlexAddress {
        IPver flag{};
        std::unique_ptr<uint8_t[]> address;
        size_t nbytes{};
        std::string strAddress;

        void parseIP() {
            nbytes = (flag == IPver::v4) ? 4u : 16u;
            address.reset(new uint8_t[nbytes]);
            if (flag == IPver::v4) {
                IN_ADDR v4{};
                if (InetPtonA(AF_INET, strAddress.c_str(), &v4) != 1) {
                    address.reset();
                    nbytes = 0;
                    throw std::invalid_argument("invalid IPv4");
                }
                std::memcpy(address.get(), &v4, 4);
            } else {
                IN6_ADDR v6{};
                if (InetPtonA(AF_INET6, strAddress.c_str(), &v6) != 1) {
                    address.reset();
                    nbytes = 0;
                    throw std::invalid_argument("invalid IPv6");
                }
                std::memcpy(address.get(), &v6, 16);
            }
        }

    public:
        FlexAddress() = default;

        FlexAddress(IPver f, const std::string& addressStr) : flag(f), strAddress(addressStr) {
            parseIP();
        }

        FlexAddress(const FlexAddress& o) : flag(o.flag), strAddress(o.strAddress), nbytes(o.nbytes) {
            if (o.address && o.nbytes) {
                address.reset(new uint8_t[o.nbytes]);
                std::memcpy(address.get(), o.address.get(), o.nbytes);
            }
        }

        FlexAddress& operator=(const FlexAddress& o) {
            if (this == &o) return *this;
            flag = o.flag;
            strAddress = o.strAddress;
            nbytes = o.nbytes;
            if (o.address && o.nbytes) {
                address.reset(new uint8_t[o.nbytes]);
                std::memcpy(address.get(), o.address.get(), o.nbytes);
            } else {
                address.reset();
                nbytes = 0;
            }
            return *this;
        }

        FlexAddress(FlexAddress&&) noexcept = default;
        FlexAddress& operator=(FlexAddress&&) noexcept = default;
        ~FlexAddress() = default;

        const std::string& getIPstr() const { return strAddress; }
        IPver version() const { return flag; }
    };
}