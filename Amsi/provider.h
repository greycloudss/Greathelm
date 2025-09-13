#pragma once
#include <windows.h>
#include <unknwn.h>
#include <atomic>

typedef LONG AMSI_RESULT;
enum AMSI_ATTRIBUTE {
    AMSI_ATTRIBUTE_APP_NAME = 0,
    AMSI_ATTRIBUTE_CONTENT_NAME = 1,
    AMSI_ATTRIBUTE_CONTENT_SIZE = 2,
    AMSI_ATTRIBUTE_CONTENT_ADDRESS = 3,
    AMSI_ATTRIBUTE_SESSION = 4,
    AMSI_ATTRIBUTE_REDIRECTION = 5,
    AMSI_ATTRIBUTE_ALL_STATUS = 6
};
#define AMSI_RESULT_NOT_DETECTED 1
#define AMSI_RESULT_DETECTED 32768

struct IAmsiStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetAttribute(DWORD attribute, ULONG dataSize, PUCHAR data, PULONG retSize) = 0;
    virtual HRESULT STDMETHODCALLTYPE Read(ULONGLONG position, ULONG size, PUCHAR buffer, PULONG readSize) = 0;
};

struct IAntimalwareProvider : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* name) = 0;
    virtual void STDMETHODCALLTYPE CloseSession(ULONGLONG session) = 0;
    virtual HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) = 0;
};

extern "C" const IID IID_IAntimalwareProvider;
extern HMODULE g_hMod;
extern const wchar_t* kProviderName;
extern const CLSID CLSID_MyProvider;

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
