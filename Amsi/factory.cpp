#include "factory.h"

HRESULT Factory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) { *ppv = static_cast<IClassFactory*>(this); AddRef(); return S_OK; }
    *ppv = nullptr; return E_NOINTERFACE;
}

ULONG Factory::AddRef() {
    long n = refCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    return (ULONG)n;
}

ULONG Factory::Release() {
    long n = refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (!n) delete this;
    return (ULONG)n;
}

HRESULT Factory::CreateInstance(IUnknown* outer, REFIID riid, void** ppv) {
    if (outer) return CLASS_E_NOAGGREGATION;
    
    Provider* p = new(std::nothrow) Provider();

    if (!p) return E_OUTOFMEMORY;

    HRESULT hr = p->QueryInterface(riid, ppv);
    p->Release();

    return hr;
}

HRESULT Factory::LockServer(BOOL) {
    return S_OK;
}
