#include "provider.h"
#include <string>
#include <cwchar>
#include <ole2.h>

HMODULE g_hMod = nullptr;
const wchar_t* kProviderName = L"My AMSI Provider";
const CLSID CLSID_MyProvider = {0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11}};
extern "C" const IID IID_IAntimalwareProvider = {0xb2cabfe3,0xfe04,0x42b1,{0xa5,0xdf,0x08,0xd4,0x83,0xd4,0xd1,0x25}};

static bool policy_allow(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < len; ++i) if (p[i] == 'I') return false;
    return true;
}

HRESULT Provider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAntimalwareProvider)) { *ppv = static_cast<IAntimalwareProvider*>(this); AddRef(); return S_OK; }
    *ppv = nullptr; return E_NOINTERFACE;
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

HRESULT Provider::DisplayName(LPWSTR* name) {
    if (!name) return E_POINTER;
    size_t c = wcslen(kProviderName) + 1;
    *name = (LPWSTR)CoTaskMemAlloc(c * sizeof(wchar_t));
    if (!*name) return E_OUTOFMEMORY;
    wcscpy_s(*name, c, kProviderName);
    return S_OK;
}

void Provider::CloseSession(ULONGLONG) {}

HRESULT Provider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_NOT_DETECTED;

    ULONGLONG sz = 0; ULONG ret = 0;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(sz), (PUCHAR)&sz, &ret);
    PUCHAR addr = nullptr;
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

            if (!policy_allow(buf.data(), read)) {
                *result = AMSI_RESULT_DETECTED;
                return S_OK;
            }

            pos += read;
        }
    }
    return S_OK;
}
