#include "provider.h"
#include <string>
#include <cwchar>
#include <ole2.h>

extern "C" const CLSID CLSID_Greathelm={0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11}};
extern "C" const IID IID_IAntimalwareProvider={0xb2cabfe3,0xfe04,0x42b1,{0xa5,0xdf,0x08,0xd4,0x83,0xd4,0xd1,0x25}};

HMODULE g_hMod=nullptr;
const wchar_t* kProviderName=L"Greathelm";

bool gh_logw(const std::wstring& msg) {
    wchar_t base[512] = L"";
    DWORD n = GetEnvironmentVariableW(L"ProgramData", base, 512);
    if (!n || n >= 512) return false;
    std::wstring dir = std::wstring(base) + L"\\Greathelm";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\events.log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t wline[2048];
    int wn = swprintf(wline, 2048, L"%04u-%02u-%02uT%02u:%02u:%02u %ls\r\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg.c_str());
    if (wn <= 0) { CloseHandle(h); return false; }
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wline, wn, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) { CloseHandle(h); return false; }
    std::string utf8; utf8.resize(bytes);
    WideCharToMultiByte(CP_UTF8, 0, wline, wn, utf8.data(), bytes, nullptr, nullptr);
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == (DWORD)utf8.size();
}

static bool policy_allow(const void* data, size_t len) {
    const wchar_t* name = LR"(\\.\pipe\AmsiPolicy)";
    for (int i = 0; i < 20; ++i) {
        if (WaitNamedPipeW(name, 250)) break;
        if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PIPE_BUSY) break;
        Sleep(50);
    }
    HANDLE h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return true;
    DWORD w = 0, r = 0, need = (DWORD)len;
    if (!WriteFile(h, &need, sizeof need, &w, nullptr)) { CloseHandle(h); return true; }
    size_t off = 0;
    while (off < len) {
        DWORD chunk = (DWORD)std::min(len - off, (size_t)65536);
        if (!WriteFile(h, (const char*)data + off, chunk, &w, nullptr) || w == 0) { CloseHandle(h); return true; }
        off += w;
    }
    char verdict = 'A';
    ReadFile(h, &verdict, 1, &r, nullptr);
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
    size_t c=wcslen(kProviderName)+1;
    *name=(LPWSTR)CoTaskMemAlloc(c*sizeof(wchar_t));
    if(!*name) return E_OUTOFMEMORY;
    wcscpy_s(*name,c,kProviderName);
    return S_OK;
}
void Provider::CloseSession(ULONGLONG){}

HRESULT Provider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_NOT_DETECTED;

    ULONGLONG sz = 0; ULONG ret = 0; PUCHAR addr = nullptr;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(sz), (PUCHAR)&sz, &ret);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(addr), (PUCHAR)&addr, &ret);

    if (addr && sz) {
        if (!policy_allow(addr, (size_t)sz)) { *result = AMSI_RESULT_DETECTED; return S_OK; }
    } else {
        const ULONG chunk = 1 << 16;
        std::string buf; buf.resize(chunk);
        ULONGLONG pos = 0;
        for (;;) {
            ULONG read = 0;
            if (FAILED(stream->Read(pos, chunk, (PUCHAR)buf.data(), &read)) || read == 0) break;
            if (!policy_allow(buf.data(), read)) { *result = AMSI_RESULT_DETECTED; return S_OK; }
            pos += read;
        }
    }

    return S_OK;
}