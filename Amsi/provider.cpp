#include "provider.h"
#include <string>
#include <cwchar>
#include <vector>
#include <ole2.h>
#include <stdint.h>

void GhModuleAddRef() noexcept;
void GhModuleRelease() noexcept;

extern "C" const CLSID CLSID_Greathelm={0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11}};
extern "C" const IID IID_IAntimalwareProvider={0xb2cabfe3,0xfe04,0x42b1,{0xa5,0xdf,0x08,0xd4,0x83,0xd4,0xd1,0x25}};

extern HMODULE g_hMod;
const wchar_t* kProviderName = L"Greathelm";

Provider::Provider() : refCount(1) { GhModuleAddRef(); }
Provider::~Provider() { GhModuleRelease(); }

static bool write_log_line(const std::wstring& path, const std::wstring& line) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    int bytes = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) { CloseHandle(h); return false; }
    std::string utf8(bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(), &utf8[0], bytes, nullptr, nullptr);
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == (DWORD)utf8.size();
}

bool gh_logw(const std::wstring& msg) {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[64];
    swprintf(ts, 64, L"%04u-%02u-%02uT%02u:%02u:%02u ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    const std::wstring line = std::wstring(ts) + msg + L"\r\n";

    wchar_t base[512] = L"";
    DWORD n = GetEnvironmentVariableW(L"ProgramData", base, 512);
    if (n && n < 512) {
        std::wstring dir = std::wstring(base) + L"\\Greathelm";
        CreateDirectoryW(dir.c_str(), nullptr);
        if (write_log_line(dir + L"\\events.log", line)) return true;
    }
    wchar_t tmp[MAX_PATH] = L"";
    if (GetTempPathW(MAX_PATH, tmp)) {
        std::wstring dir = std::wstring(tmp) + L"Greathelm";
        CreateDirectoryW(dir.c_str(), nullptr);
        if (write_log_line(dir + L"\\events-provider.log", line)) return true;
    }
    return false;
}

static bool policy_allow(const uint8_t* data, size_t len) {
    if (!data || len == 0) return true;

    const DWORD kMaxMsg = 262144;
    const DWORD kWaitMs = 2000;
    DWORD toSend = (DWORD)(len > kMaxMsg ? kMaxMsg : len);

    if (!WaitNamedPipeW(LR"(\\.\pipe\AmsiPolicy)", kWaitMs)) {
        static int logCount = 0;
        if (logCount < 5 || (logCount % 10) == 0) {
            gh_logw(L"policy_allow: WaitNamedPipe failed err=" + to_wstring_utf8(std::to_string(GetLastError())));
        }
        ++logCount;
        return true;
    }

    HANDLE h = CreateFileW(LR"(\\.\pipe\AmsiPolicy)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        static int logCount = 0;
        if (logCount < 5 || (logCount % 10) == 0) {
            gh_logw(L"policy_allow: CreateFile pipe failed err=" + to_wstring_utf8(std::to_string(GetLastError())));
        }
        ++logCount;
        return true;
    }

    DWORD w = 0;
    if (!WriteFile(h, &toSend, sizeof(toSend), &w, nullptr) || w != sizeof(toSend)) {
        CloseHandle(h);
        return true;
    }

    const BYTE* p = data;
    DWORD remaining = toSend;
    while (remaining) {
        DWORD chunk = remaining > 65536 ? 65536 : remaining;
        if (!WriteFile(h, p, chunk, &w, nullptr) || w == 0) {
            CloseHandle(h);
            return true;
        }
        p += w;
        remaining -= w;
    }

    BYTE verdict = 'A';
    DWORD r = 0;
    if (!ReadFile(h, &verdict, 1, &r, nullptr) || r != 1) {
        CloseHandle(h);
        return true;
    }

    CloseHandle(h);
    return verdict != 'D';
}


HRESULT Provider::QueryInterface(REFIID riid, void** ppv) {
    if (ppv) *ppv = nullptr;
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAntimalwareProvider)) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

ULONG Provider::AddRef() {
    long n = refCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    return (ULONG)n;
}

ULONG Provider::Release() {
    long n = refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (!n) delete this;
    return (ULONG)n;
}

HRESULT Provider::DisplayName(LPWSTR* name){
    if(!name) return E_POINTER;
    size_t c = wcslen(kProviderName) + 1;
    *name = (LPWSTR)CoTaskMemAlloc(c * sizeof(wchar_t));
    if(!*name) return E_OUTOFMEMORY;
    wcscpy_s(*name, c, kProviderName);
    return S_OK;
}

void Provider::CloseSession(ULONGLONG) {}

static std::string hex_head(const uint8_t* p, size_t n) {
    size_t m = n < 16 ? n : 16;

    static const char* hexdigits = "0123456789abcdef";

    std::string hex;
    hex.reserve(m * 2);

    for (size_t i = 0; i < m; ++i) {
        uint8_t b = p[i];
        hex.push_back(hexdigits[b >> 4]);
        hex.push_back(hexdigits[b & 0x0F]);
    }

    std::string ascii;
    ascii.reserve(m);

    for (size_t i = 0; i < m; ++i) {
        unsigned char c = p[i];
        ascii.push_back(c >= 32 && c < 127 ? char(c) : '.');
    }

    return hex + " " + ascii;
}

HRESULT Provider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    gh_logw(L"SCAN begin (provider)");
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_NOT_DETECTED;

    ULONGLONG sz = 0;
    ULONG ret = 0;
    PUCHAR addr = nullptr;

    HRESULT hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(sz), (PUCHAR)&sz, &ret);
    if (FAILED(hr)) {
        gh_logw(std::wstring(L"SCAN: GetAttribute(size) failed hr=") + to_wstring_utf8(std::to_string(hr)));
    }

    hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(addr), (PUCHAR)&addr, &ret);
    if (FAILED(hr)) {
    }

    const size_t maxInspect = 262144; // 256KiB
    size_t inspectLen = 0;

    try {
        if (addr && sz) {
            inspectLen = (size_t)(sz > maxInspect ? maxInspect : (size_t)sz);
            gh_logw(std::wstring(L"SCAN: attr direct size=") + std::to_wstring((unsigned long long)sz) + L" head=" + to_wstring_utf8(hex_head((const uint8_t*)addr, inspectLen)));
            if (!policy_allow(reinterpret_cast<const uint8_t*>(addr), inspectLen)) { *result = AMSI_RESULT_DETECTED; return S_OK; }
            return S_OK;
        }

        const ULONG chunk = 1 << 16;
        std::vector<char> buf(chunk);
        ULONGLONG pos = 0;
        size_t totalRead = 0;
        for (;;) {
            ULONG read = 0;
            hr = stream->Read(pos, chunk, (PUCHAR)buf.data(), &read);
            if (FAILED(hr) || read == 0) break;
            totalRead += read;
            if (totalRead > maxInspect) {
                gh_logw(L"SCAN: chunked read exceeded cap, stopping inspect");
                break;
            }
            if (pos == 0) {
                gh_logw(std::wstring(L"SCAN: chunked first read size=") + std::to_wstring(read) + L" head=" + to_wstring_utf8(hex_head((const uint8_t*)buf.data(), (size_t)read)));
            }
            if (!policy_allow(reinterpret_cast<const uint8_t*>(buf.data()), read)) { *result = AMSI_RESULT_DETECTED; return S_OK; }
            pos += read;
        }
    } catch (const std::bad_alloc&) {
        gh_logw(L"SCAN: bad_alloc while scanning - allowing");
        return S_OK;
    } catch (...) {
        gh_logw(L"SCAN: unexpected exception - allowing");
        return S_OK;
    }

    return S_OK;
}
