#include "provider.h"
#include <string>
#include <cwchar>
#include <ole2.h>

void GhModuleAddRef() noexcept;
void GhModuleRelease() noexcept;

extern "C" const CLSID CLSID_Greathelm={0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11}};
extern "C" const IID IID_IAntimalwareProvider={0xb2cabfe3,0xfe04,0x42b1,{0xa5,0xdf,0x08,0xd4,0x83,0xd4,0xd1,0x25}};

HMODULE g_hMod = nullptr;
const wchar_t* kProviderName=L"Greathelm";

Provider::Provider() : refCount(1) {
    GhModuleAddRef();
}

static bool write_log_line(const std::wstring& path, const std::wstring& line) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    int bytes = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) { CloseHandle(h); return false; }
    std::string utf8(bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(), utf8.data(), bytes, nullptr, nullptr);
    DWORD wrote = 0; BOOL ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wrote, nullptr);
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
    constexpr DWORD kTimeoutMs = 800;
    constexpr DWORD kMaxMsg    = 262144;

    static std::atomic<bool> s_logWaitFail{false};
    static std::atomic<bool> s_logOpenFail{false};
    static std::atomic<bool> s_logWriteFail{false};
    static std::atomic<bool> s_logReadFail{false};

    if (!data || len == 0) return true;

    DWORD toSend = (DWORD) (len > kMaxMsg ? kMaxMsg : len);

    if (!WaitNamedPipeW(LR"(\\.\pipe\AmsiPolicy)", kTimeoutMs)) {
        if (!s_logWaitFail.exchange(true)) {
            wchar_t buf[64]; swprintf(buf, 64, L"PIPE_FAIL: wait (%lu)", GetLastError());
            gh_logw(buf);
        }
        return true;
    }

    HANDLE h = CreateFileW(LR"(\\.\pipe\AmsiPolicy)", GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (!s_logOpenFail.exchange(true)) {
            wchar_t buf[64]; swprintf(buf, 64, L"PIPE_FAIL: open (%lu)", GetLastError());
            gh_logw(buf);
        }
        return true;
    }

    OVERLAPPED ovw{}; OVERLAPPED ovr{};
    ovw.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ovr.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ovw.hEvent || !ovr.hEvent) {
        if (ovw.hEvent) CloseHandle(ovw.hEvent);
        if (ovr.hEvent) CloseHandle(ovr.hEvent);
        CloseHandle(h);
        return true;
    }

    auto cleanup = [&](){
        CloseHandle(ovw.hEvent);
        CloseHandle(ovr.hEvent);
        CloseHandle(h);
    };

    DWORD written = 0;
    if (!WriteFile(h, &toSend, sizeof(toSend), nullptr, &ovw)) {
        if (GetLastError()!=ERROR_IO_PENDING ||
            WaitForSingleObject(ovw.hEvent, kTimeoutMs)!=WAIT_OBJECT_0 ||
            !GetOverlappedResult(h, &ovw, &written, FALSE) || written!=sizeof(toSend)) {
            if (!s_logWriteFail.exchange(true)) gh_logw(L"PIPE_FAIL: write(size)");
            cleanup(); return true;
        }
    }

    const BYTE* p = reinterpret_cast<const BYTE*>(data);
    DWORD remaining = toSend;
    while (remaining) {
        ResetEvent(ovw.hEvent);
        const DWORD chunk = remaining > 65536 ? 65536 : remaining;
        if (!WriteFile(h, p, chunk, nullptr, &ovw)) {
            if (GetLastError()!=ERROR_IO_PENDING ||
                WaitForSingleObject(ovw.hEvent, kTimeoutMs)!=WAIT_OBJECT_0) {
                if (!s_logWriteFail.exchange(true)) gh_logw(L"PIPE_FAIL: write(data)");
                cleanup(); return true;
            }
            DWORD got = 0;
            if (!GetOverlappedResult(h, &ovw, &got, FALSE) || got==0) {
                if (!s_logWriteFail.exchange(true)) gh_logw(L"PIPE_FAIL: write(zero)");
                cleanup(); return true;
            }
            written = got;
        } else {
            written = chunk;
        }
        p += written;
        remaining -= written;
    }

    BYTE verdict = 'A';
    ResetEvent(ovr.hEvent);
    if (!ReadFile(h, &verdict, 1, nullptr, &ovr)) {
        if (GetLastError()!=ERROR_IO_PENDING ||
            WaitForSingleObject(ovr.hEvent, kTimeoutMs)!=WAIT_OBJECT_0) {
            if (!s_logReadFail.exchange(true)) gh_logw(L"PIPE_FAIL: read(verdict)");
            cleanup(); return true;
        }
        DWORD got = 0;
        if (!GetOverlappedResult(h, &ovr, &got, FALSE) || got!=1) {
            if (!s_logReadFail.exchange(true)) gh_logw(L"PIPE_FAIL: read(size)");
            cleanup(); return true;
        }
    }

    cleanup();
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
    size_t c=wcslen(kProviderName)+1;
    *name=(LPWSTR)CoTaskMemAlloc(c*sizeof(wchar_t));
    if(!*name) return E_OUTOFMEMORY;
    wcscpy_s(*name,c,kProviderName);
    return S_OK;
}
void Provider::CloseSession(ULONGLONG){}

HRESULT Provider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    static std::atomic<bool> s_loggedScan{false};
    if (!s_loggedScan.exchange(true)) gh_logw(L"SCAN begin (provider)");
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_NOT_DETECTED;
    gh_logw(L"2");
    ULONGLONG sz = 0; ULONG ret = 0; PUCHAR addr = nullptr;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(sz), (PUCHAR)&sz, &ret);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(addr), (PUCHAR)&addr, &ret);
    gh_logw(L"3");
    if (addr && sz) {
        if (!policy_allow(addr, (size_t)sz)) { *result = AMSI_RESULT_DETECTED; return S_OK; }
         gh_logw(L"4");
    } else {
        const ULONG chunk = 1 << 16;
        std::string buf; buf.resize(chunk);
        ULONGLONG pos = 0;
        gh_logw(L"5");
        for (;;) {
            gh_logw(L"6");
            ULONG read = 0;
            if (FAILED(stream->Read(pos, chunk, (PUCHAR)buf.data(), &read)) || read == 0) break;
            if (!policy_allow(reinterpret_cast<const uint8_t*>(buf.data()), read)) {
                *result = AMSI_RESULT_DETECTED; return S_OK;
            }
            pos += read;
        }
        gh_logw(L"7");
    }
    gh_logw(L"8");
    return S_OK;
}


Provider::~Provider() {
    GhModuleRelease();
}