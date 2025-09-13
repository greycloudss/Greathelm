#include <windows.h>
#include <unknwn.h>
#include "factory.h"
#include "provider.h"

extern "C" BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!IsEqualCLSID(rclsid, CLSID_MyProvider)) {
        if (ppv) *ppv = 0;
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    Factory* f = new(std::nothrow) Factory();

    if (!f) return E_OUTOFMEMORY;

    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    
    return hr;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow() {
    return S_OK;
}



