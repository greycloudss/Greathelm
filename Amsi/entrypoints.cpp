#include <windows.h>
#include <unknwn.h>
#include "factory.h"
#include "provider.h"

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, CLSID_Greathelm)) return CLASS_E_CLASSNOTAVAILABLE;
    ClassFactory* f = new(std::nothrow) ClassFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow() {
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t buf[128];
        swprintf(buf, 128, L"PROVIDER: loaded pid=%lu", GetCurrentProcessId());
        gh_logw(buf);
    }
    return TRUE;
}
