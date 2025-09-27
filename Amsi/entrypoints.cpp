#include <windows.h>
#include <unknwn.h>
#include "factory.h"
#include "provider.h"
#include <atomic>
#include <strsafe.h>

#if defined(__GNUC__)
    #define DLL_EXPORT __attribute__((dllexport))
#else
    #define DLL_EXPORT __declspec(dllexport)
#endif

static std::atomic<long> g_objCount{0};
static std::atomic<long> g_lockCount{0};

void GhModuleAddRef()      noexcept { g_objCount.fetch_add(1, std::memory_order_relaxed); }
void GhModuleRelease()     noexcept { g_objCount.fetch_sub(1, std::memory_order_relaxed); }
void GhLockServerAddRef()  noexcept { g_lockCount.fetch_add(1, std::memory_order_relaxed); }
void GhLockServerRelease() noexcept { g_lockCount.fetch_sub(1, std::memory_order_relaxed); }

extern "C" const CLSID CLSID_Greathelm;

static HRESULT RegWriteStr(HKEY root, const wchar_t* subkey,
                           const wchar_t* name, const wchar_t* value) {
    HKEY k = nullptr;
    LONG rc = RegCreateKeyExW(root, subkey, 0, nullptr, 0,
                              KEY_SET_VALUE, nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) return HRESULT_FROM_WIN32(rc);
    rc = RegSetValueExW(k, name, 0, REG_SZ,
                        (const BYTE*)value,
                        (DWORD)((wcslen(value)+1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return HRESULT_FROM_WIN32(rc == ERROR_SUCCESS ? ERROR_SUCCESS : rc);
}

static std::wstring GuidToBracedString(const CLSID& clsid) {
    wchar_t buf[64] = {};
    StringFromGUID2(clsid, buf, 64);
    return std::wstring(buf);
}

STDAPI DllRegisterServer(void) {
    if (!g_hMod) return E_UNEXPECTED;

    wchar_t path[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_hMod, path, MAX_PATH)) return HRESULT_FROM_WIN32(GetLastError());

    const std::wstring clsid = GuidToBracedString(CLSID_Greathelm);

    std::wstring keyClsid   = L"CLSID\\" + clsid;
    std::wstring keyInproc  = keyClsid + L"\\InprocServer32";
    HRESULT hr;
    
    hr = RegWriteStr(HKEY_CLASSES_ROOT, keyClsid.c_str(),       nullptr, L"Greathelm AMSI Provider");
    if (FAILED(hr)) return hr;
    
    hr = RegWriteStr(HKEY_CLASSES_ROOT, keyInproc.c_str(),      nullptr, path);
    if (FAILED(hr)) return hr;

    hr = RegWriteStr(HKEY_CLASSES_ROOT, keyInproc.c_str(),      L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

    const wchar_t* AMSI_BASE = L"SOFTWARE\\Microsoft\\AMSI";
    std::wstring keyProv  = std::wstring(AMSI_BASE) + L"\\Providers\\"  + clsid;
    std::wstring keyProv2 = std::wstring(AMSI_BASE) + L"\\Providers2\\" + clsid;

    hr = RegWriteStr(HKEY_LOCAL_MACHINE, keyProv.c_str(),  nullptr, L"Greathelm");
    if (FAILED(hr)) return hr;

    hr = RegWriteStr(HKEY_LOCAL_MACHINE, keyProv2.c_str(), nullptr, L"Greathelm");
    if (FAILED(hr)) return hr;

    return S_OK;
}

STDAPI DllUnregisterServer(void) {
    const std::wstring clsid = GuidToBracedString(CLSID_Greathelm);

    const wchar_t* AMSI_BASE = L"SOFTWARE\\Microsoft\\AMSI";
    std::wstring keyProv  = std::wstring(AMSI_BASE) + L"\\Providers\\"  + clsid;
    std::wstring keyProv2 = std::wstring(AMSI_BASE) + L"\\Providers2\\" + clsid;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyProv.c_str());
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyProv2.c_str());

    std::wstring keyInproc  = L"CLSID\\" + clsid + L"\\InprocServer32";
    std::wstring keyClsid   = L"CLSID\\" + clsid;
    RegDeleteKeyW(HKEY_CLASSES_ROOT, keyInproc.c_str());
    RegDeleteKeyW(HKEY_CLASSES_ROOT, keyClsid.c_str());
    return S_OK;
}