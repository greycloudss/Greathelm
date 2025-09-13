#pragma once
#include <windows.h>
#include <unknwn.h>
#include <amsi.h>
#include <string>
#include <cwchar>
#include <atomic>

static HMODULE g_hMod = nullptr;
static const wchar_t* kProviderName = L"Greathelm";
static const CLSID CLSID_MyProvider = {0x5f3e9c28,0x3e4a,0x4a8a,{0x9b,0x0c,0x9c,0x42,0x3e,0x3a,0xa7,0x11}};

//add actual pipeline
static bool policy_allow(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < len; ++i)
        if (p[i] == 'I')
            return false;
    return true;
}

class Provider : public IAntimalwareProvider {
    std::atomic<long> refCount{1};
    
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;
    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* name) override;
    void STDMETHODCALLTYPE CloseSession(ULONGLONG) override;
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override;

};