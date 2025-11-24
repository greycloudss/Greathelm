#include "defender.h"
#include <ws2tcpip.h>
#include "../util/strings.h"

namespace ESC {
    namespace {
        struct TempBlockCtx {
            Firewall* fw;
            FlexAddress addr;
            DWORD duration;
        };

        DWORD WINAPI TempBlockThread(LPVOID param) {
            auto* ctx = static_cast<TempBlockCtx*>(param);
            if (!ctx) return 1;
            try {
                if (ctx->fw) {
                    ctx->fw->addBlock(&ctx->addr);
                    Sleep(ctx->duration);
                    ctx->fw->removeBlock(&ctx->addr);
                }
            } catch (...) {
            }
            delete ctx;
            return 0;
        }
    }

    Defender::Defender() : registry(new Registry()), powershell(new Powershell()), firewall(new Firewall()) {
        if (powershell) {
            powershell->setTargetCallback([this](const std::vector<std::string>& targets) {
                this->handleTargets(targets);
            });
        }
    }

    void Defender::run() {
        if (registry) {
            if (registry->start()) UTIL::logSuspicion(L"[Defender] registry monitoring started");
            else UTIL::logSuspicion(L"[Defender] registry monitoring failed to start");
        }

        if (powershell) {
            if (powershell->start()) UTIL::logSuspicion(L"[Defender] PowerShell monitor started");
            else UTIL::logSuspicion(L"[Defender] PowerShell monitor failed to start");
        }
    }

    void Defender::handleTargets(const std::vector<std::string>& targets) {
        if (!firewall || targets.empty()) return;

        for (const auto& t : targets) {
            FlexAddress* addr = nullptr;
            IN_ADDR v4{};
            IN6_ADDR v6{};
            if (InetPtonA(AF_INET, t.c_str(), &v4) == 1) {
                addr = new FlexAddress(IPver::v4, t);
            } else if (InetPtonA(AF_INET6, t.c_str(), &v6) == 1) {
                addr = new FlexAddress(IPver::v6, t);
            } else {
                std::wstring w = UTIL::to_wstring_utf8(t);
                addr = firewall->parseURL(w);
            }

            if (!addr) continue;

            std::wstring msg = L"[Defender] temporary firewall block from PowerShell target: " + UTIL::to_wstring_utf8(addr->getIPstr());
            UTIL::logSuspicion(msg);
            blockForDuration(*addr, 5000);
            delete addr;
        }
    }

    void Defender::blockForDuration(const FlexAddress& ip, DWORD durationMs) {
        if (!firewall) return;
        auto* ctx = new TempBlockCtx{ firewall, ip, durationMs };
        HANDLE h = CreateThread(nullptr, 0, TempBlockThread, ctx, 0, nullptr);
        if (h) CloseHandle(h);
    }

    void Defender::escalate(const std::string& command) {
        handleTargets(Powershell::findTargets(command));
    }

    Defender::~Defender() {
        if (powershell) {
            powershell->stop();
            delete powershell;
            powershell = nullptr;
        }
        if (registry) {
            registry->stop();
            delete registry;
            registry = nullptr;
        }
        if (firewall) {
            delete firewall;
            firewall = nullptr;
        }
    }
};
