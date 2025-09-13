#include "provider.h"

HRESULT STDMETHODCALLTYPE Provider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAntimalwareProvider)) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }

    *ppv = nullptr; return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE Provider::AddRef() {
    long n = refCount.fetch_add(1, std::memory_order_acq_rel) + 1;

    return (ULONG)n;
}

ULONG STDMETHODCALLTYPE Provider::Release() {
    long n = refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;

    if (!n) delete this;

    return (ULONG)n;
}

HRESULT STDMETHODCALLTYPE Provider::DisplayName(LPWSTR* name) {
    if (!name) return E_POINTER;

    size_t c = wcslen(kProviderName) + 1;

    *name = (LPWSTR)CoTaskMemAlloc(c * sizeof(wchar_t));

    if (!*name) return E_OUTOFMEMORY;

    wcscpy_s(*name, c, kProviderName);

    return S_OK;
}

void STDMETHODCALLTYPE Provider::CloseSession(ULONGLONG) {}

HRESULT STDMETHODCALLTYPE Provider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    if (!stream || !result) return E_INVALIDARG;

    *result = AMSI_RESULT_NOT_DETECTED;

    ULONGLONG sz = 0; ULONG ret = 0;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(sz), (PUCHAR)&sz, &ret);

    PUCHAR addr = nullptr;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(addr), (PUCHAR)&addr, &ret);

    if (addr && sz) {
        if (!policy_allow(addr, (size_t)sz)) *result = AMSI_RESULT_DETECTED; return S_OK; 

    } else {
        const ULONG chunk = 1<<16;
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