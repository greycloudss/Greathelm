#pragma once
#include <windows.h>
#include <unknwn.h>
#include <atomic>
#include <string>

extern "C" const CLSID CLSID_Greathelm;

bool gh_logw(const std::wstring& msg);

typedef LONG AMSI_RESULT;
enum AMSI_ATTRIBUTE { AMSI_ATTRIBUTE_APP_NAME=0, AMSI_ATTRIBUTE_CONTENT_NAME=1, AMSI_ATTRIBUTE_CONTENT_SIZE=2, AMSI_ATTRIBUTE_CONTENT_ADDRESS=3, AMSI_ATTRIBUTE_SESSION=4, AMSI_ATTRIBUTE_REDIRECTION=5, AMSI_ATTRIBUTE_ALL_STATUS=6 };
#define AMSI_RESULT_NOT_DETECTED 1
#define AMSI_RESULT_DETECTED     32768

struct IAmsiStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetAttribute(DWORD, ULONG, PUCHAR, PULONG) = 0;
    virtual HRESULT STDMETHODCALLTYPE Read(ULONGLONG, ULONG, PUCHAR, PULONG) = 0;
};
struct IAntimalwareProvider : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR*) = 0;
    virtual void    STDMETHODCALLTYPE CloseSession(ULONGLONG) = 0;
    virtual HRESULT STDMETHODCALLTYPE Scan(IAmsiStream*, AMSI_RESULT*) = 0;
};

extern "C" const IID IID_IAntimalwareProvider;
extern HMODULE g_hMod;
extern const wchar_t* kProviderName;

class Provider : public IAntimalwareProvider {
    std::atomic<long> refCount{1};
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;
    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR*) override;
    void    STDMETHODCALLTYPE CloseSession(ULONGLONG) override;
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream*, AMSI_RESULT*) override;
    Provider();
    virtual ~Provider();
};
