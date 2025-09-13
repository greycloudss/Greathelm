#pragma once
#include <windows.h>
#include <unknwn.h>
#include "provider.h"

class Factory : public IClassFactory {
    std::atomic<long> refCount{1};
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override;
    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override;
};
