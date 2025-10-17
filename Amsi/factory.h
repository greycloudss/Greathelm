#pragma once
#include <windows.h>
#include <unknwn.h>
#include <atomic>

class Provider;

class ClassFactory : public IClassFactory {
    std::atomic<long> refCount{1};
public:
    virtual ~ClassFactory() noexcept {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID,void**) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown*,REFIID,void**) override;
    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override;
};
