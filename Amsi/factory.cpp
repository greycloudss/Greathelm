#include "factory.h"
#include "provider.h"
#include <new>

void GhLockServerAddRef() noexcept;
void GhLockServerRelease() noexcept;

HRESULT ClassFactory::QueryInterface(REFIID riid, void** ppv) {
    if (ppv) *ppv = nullptr;
    if (!ppv) return E_POINTER;
    
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

ULONG ClassFactory::AddRef() {
    long n = refCount.fetch_add(1, std::memory_order_acq_rel) + 1;

    return (ULONG)n;
}

ULONG ClassFactory::Release() {
    long n = refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (!n) delete this;

    return (ULONG)n;
}

HRESULT ClassFactory::CreateInstance(IUnknown* outer, REFIID riid, void** ppv) {
    if (ppv) *ppv = nullptr;
    if (!ppv) return E_POINTER;
    if (outer) return CLASS_E_NOAGGREGATION;

    Provider* p = new(std::nothrow) Provider();

    if (!p) return E_OUTOFMEMORY;

    HRESULT hr = p->QueryInterface(riid, ppv);

    if (FAILED(hr)) delete p;

    return hr;
}

HRESULT ClassFactory::LockServer(BOOL fLock) {
    if (fLock) {
        GhLockServerAddRef();
    } else {
        GhLockServerRelease();
    }
    return S_OK;
}