#include "powershell.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <utility>

namespace ESC {
    namespace {
        struct AnalysisCtx {
            Powershell* self;
            std::vector<uint8_t> data;
        };

        DWORD WINAPI AnalyzePayloadAsync(LPVOID param) {
            std::unique_ptr<AnalysisCtx> ctx(static_cast<AnalysisCtx*>(param));
            if (!ctx || !ctx->self) return 0;

            try {
                std::string text = ctx->self->bytes_to_text(ctx->data.data(), ctx->data.size());
                std::vector<std::string> targets = Powershell::findTargets(text);
                const bool hasTargets = !targets.empty();
                const bool hasKeywords = ctx->self->contains_ps_keyword(text);
                const size_t previewLen = 160;
                std::string preview = text.substr(0, previewLen);
                if (text.size() > previewLen) preview += "...";

                if (!targets.empty()) ctx->self->notifyTargets(targets);

                std::vector<std::string> regpaths = Powershell::findRegistryPaths(text);
                auto looksLikeRegistryIoc = [](const std::string& p)->bool {
                    if (p.empty()) return false;
                    static const std::vector<std::string> patterns = {
                        "\\software\\microsoft\\windows\\currentversion\\run",
                        "\\software\\microsoft\\windows\\currentversion\\runonce",
                        "\\software\\microsoft\\windows\\currentversion\\policies\\system",
                        "\\software\\microsoft\\windows nt\\currentversion\\winlogon",
                        "\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
                        "\\software\\microsoft\\windows nt\\currentversion\\silentprocessexit",
                        "\\microsoft\\windows\\currentversion\\startupapproved",
                        "\\system\\currentcontrolset\\services",
                        "\\system\\currentcontrolset\\control\\terminal server",
                        "\\system\\currentcontrolset\\control\\lsa"
                    };
                    std::string lower;
                    lower.reserve(p.size());
                    for (char c : p) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                    for (const auto& pat : patterns) {
                        if (!pat.empty() && lower.find(pat) != std::string::npos) return true;
                    }
                    return false;
                };

                for (const auto& rp : regpaths) {
                    if (!looksLikeRegistryIoc(rp)) continue;
                    UTIL::logSuspicion(L"[PowerShell] registry path detected: " + UTIL::to_wstring_utf8(rp));
                }

                if (hasTargets || hasKeywords) {
                    std::wstring msg = L"[PowerShell] suspicious content detected; logging only. ";
                    if (hasTargets) {
                        msg += L"Targets: ";
                        for (size_t i = 0; i < targets.size(); ++i) {
                            if (i) msg += L", ";
                            msg += UTIL::to_wstring_utf8(targets[i]);
                        }
                        msg += L". ";
                    }
                    msg += L"Preview: " + UTIL::to_wstring_utf8(preview);
                    UTIL::logSuspicion(msg);
                } else {
                    // Minimal breadcrumb to verify AMSI scanning without spamming.
                    UTIL::logSuspicion(L"[PowerShell] AMSI scan observed (no IOC). Preview: " + UTIL::to_wstring_utf8(preview));
                }
            } catch (...) {
            }
            return 0;
        }
    }

    Powershell::Powershell() : threadHandle(nullptr), stopEvent(nullptr), running(false) {}

    Powershell::~Powershell() {
        stop();
    }

    void Powershell::setTargetCallback(const std::function<void(const std::vector<std::string>&)>& cb) {
        targetCallback = cb;
    }

    void Powershell::notifyTargets(const std::vector<std::string>& targets) {
        if (targetCallback) {
            try { targetCallback(targets); } catch (...) {}
        }
    }

    bool Powershell::start() {
        if (running) return true;
        stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stopEvent) return false;
        running = true;
        threadHandle = CreateThread(nullptr, 0, &Powershell::ThreadProc, this, 0, nullptr);
        if (!threadHandle) {
            running = false;
            CloseHandle(stopEvent);
            stopEvent = nullptr;
            return false;
        }
        return true;
    }

    void Powershell::stop() {
        if (!running) return;
        running = false;
        if (stopEvent) SetEvent(stopEvent);
        if (threadHandle) {
            WaitForSingleObject(threadHandle, 2000);
            CloseHandle(threadHandle);
            threadHandle = nullptr;
        }
        if (stopEvent) {
            CloseHandle(stopEvent);
            stopEvent = nullptr;
        }
    }

    DWORD WINAPI Powershell::ThreadProc(LPVOID ctx) {
        auto* self = static_cast<Powershell*>(ctx);
        if (!self) return 1;
        return self->AmsiPolicyServer();
    }

    bool Powershell::looks_utf16le(const uint8_t* data, size_t len) {
        if (!data || len < 2) return false;
        size_t pairs = len / 2;
        
        if (pairs == 0) return false;
        size_t zeros = 0;

        for (size_t i = 1; i + 1 <= len; i += 2)
            if (data[i] == 0) ++zeros;
        
        return zeros * 4 >= pairs * 3;
    }

    std::string Powershell::utf16le_to_utf8(const uint8_t* data, size_t len) {
        if (!data || len < 2 || (len % 2) != 0) return std::string();
        const wchar_t* w = reinterpret_cast<const wchar_t*>(data);
        
        int wchar_count = (int)(len / 2);
        int needed = WideCharToMultiByte(CP_UTF8, 0, w, wchar_count, nullptr, 0, nullptr, nullptr);

        if (needed <= 0) return std::string();

        std::string out;
        out.resize(needed);
        WideCharToMultiByte(CP_UTF8, 0, w, wchar_count, &out[0], needed, nullptr, nullptr);

        return out;
    }

    std::string Powershell::bytes_to_text(const uint8_t* data, size_t len) {
        if (!data || len == 0) return std::string();

        if (looks_utf16le(data, len)) {
            std::string u8 = utf16le_to_utf8(data, len);

            if (!u8.empty()) return u8;
        }

        return std::string(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data) + len);
    }

    std::string Powershell::ascii_lower(const std::string& s) {
        std::string out;
        out.resize(s.size());

        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c >= 'A' && c <= 'Z') out[i] = static_cast<char>(c - 'A' + 'a');

            else out[i] = s[i];
        }

        return out;
    }

    std::string Powershell::strip_spaces(const std::string& s) {
        std::string out;
        out.reserve(s.size());

        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (!std::isspace(c)) out.push_back(s[i]);
        }

        return out;
    }

    bool Powershell::contains_ps_keyword(const std::string& text) {
        if (text.empty()) return false;

        std::string norm = ascii_lower(text);
        std::string norm_nospace = strip_spaces(norm);

        for (const auto& kv : ESC::Powershell::psStrings) {
            const std::string& key = kv.first;
            if (key.empty()) continue;
            std::string key_norm = ascii_lower(key);

            if (norm.find(key_norm) != std::string::npos) return true;
            std::string key_norm_nospace = strip_spaces(key_norm);

            if (!key_norm_nospace.empty() && norm_nospace.find(key_norm_nospace) != std::string::npos) return true;
        }
        return false;
    }

    std::vector<std::string> Powershell::findTargets(const std::string& text) {
        std::vector<std::string> out;
        if (text.empty()) return out;

        try {
            static const std::regex ipv4(R"((\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b))", std::regex::icase);
            static const std::regex ipv6(R"((\b(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}\b))", std::regex::icase);
            static const std::regex url(R"(((?:https?|ftp)://[^\s'"]+))", std::regex::icase);

            auto addMatches = [&out](const std::regex& re, const std::string& input) {
                for (std::sregex_iterator it(input.begin(), input.end(), re), end; it != end; ++it) {
                    std::string v = it->str();
                    if (!v.empty()) out.push_back(v);
                }
            };

            addMatches(ipv4, text);
            addMatches(ipv6, text);
            addMatches(url, text);

            std::sort(out.begin(), out.end());
            out.erase(std::unique(out.begin(), out.end()), out.end());
        } catch (...) {
        }

        return out;
    }

    std::vector<std::string> Powershell::findRegistryPaths(const std::string& text) {
        std::vector<std::string> out;
        if (text.empty()) return out;

        try {
            static const std::regex regpath(
                R"((HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)[:\\][^\s'"]+)",
                std::regex::icase);

            for (std::sregex_iterator it(text.begin(), text.end(), regpath), end; it != end; ++it) {
                std::string v = it->str();
                if (!v.empty()) out.push_back(v);
            }

            std::sort(out.begin(), out.end());
            out.erase(std::unique(out.begin(), out.end()), out.end());
        } catch (...) {
        }

        return out;
    }

    DWORD Powershell::AmsiPolicyServer() {
        const wchar_t* pipeName = LR"(\\.\pipe\AmsiPolicy)";
        const DWORD kMaxMsg = 262144;
        UTIL::logSuspicion(L"[PowerShell] AmsiPolicy server starting");
        for (;;) {
            if (stopEvent && WaitForSingleObject(stopEvent, 0) != WAIT_TIMEOUT) break;

            HANDLE pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, nullptr);
            
            if (pipe == INVALID_HANDLE_VALUE) {
                Sleep(500);
                continue;
            }

            BOOL connected = ConnectNamedPipe(pipe, nullptr);
            if (!connected) {
                DWORD err = GetLastError();
                if (err != ERROR_PIPE_CONNECTED) {
                    CloseHandle(pipe);
                    Sleep(100);
                    continue;
                }
            }

            if (stopEvent && WaitForSingleObject(stopEvent, 0) != WAIT_TIMEOUT) {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                break;
            }

            DWORD len = 0;
            DWORD got = 0;
            if (!ReadFile(pipe, &len, sizeof(len), &got, nullptr) || got != sizeof(len) || len == 0 || len > kMaxMsg) {
                BYTE verdict = 'A';
                DWORD written = 0;
                WriteFile(pipe, &verdict, 1, &written, nullptr);
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                continue;
            }

            std::vector<uint8_t> buffer;
            buffer.resize(len);
            DWORD total = 0;
            while (total < len) {
                DWORD chunk = 0;
                if (!ReadFile(pipe, buffer.data() + total, len - total, &chunk, nullptr) || chunk == 0) {
                    break;
                }
                total += chunk;
            }

            BYTE verdict = 'A'; // always allow to avoid PowerShell crashes; analysis/logging happens asynchronously below.
            DWORD written = 0;
            WriteFile(pipe, &verdict, 1, &written, nullptr);
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);

            // Analyze and log in the background to keep AMSI fast and avoid hangs.
            if (total == len) {
                auto* ctx = new AnalysisCtx();
                ctx->self = this;
                ctx->data.swap(buffer);
                HANDLE h = CreateThread(nullptr, 0, AnalyzePayloadAsync, ctx, 0, nullptr);
                if (h) CloseHandle(h);
                else delete ctx;
            }
        }

        return 0;
    }
};
