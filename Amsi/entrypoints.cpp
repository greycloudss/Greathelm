// entrypoints.cpp
#include <windows.h>
#include <unknwn.h>
#include "factory.h"
#include "provider.h"
#include <atomic>
#include <strsafe.h>
#include <string>
#include <new>

#if defined(__GNUC__)
    #define DLL_EXPORT __attribute__((dllexport))
#else
    #define DLL_EXPORT __declspec(dllexport)
#endif

static std::atomic<long> g_objCount{0};
static std::atomic<long> g_lockCount{0};
HMODULE g_hMod;

void GhModuleAddRef() noexcept {
    g_objCount.fetch_add(1, std::memory_order_relaxed);
}
void GhModuleRelease() noexcept {
    g_objCount.fetch_sub(1, std::memory_order_relaxed);
}
void GhLockServerAddRef() noexcept {
    g_lockCount.fetch_add(1, std::memory_order_relaxed);
}
void GhLockServerRelease() noexcept {
    g_lockCount.fetch_sub(1, std::memory_order_relaxed);
}

extern "C" const CLSID CLSID_Greathelm;

extern "C" BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) { g_hMod = (HMODULE)h; DisableThreadLibraryCalls(h); }
    return TRUE;
}

extern "C" DLL_EXPORT HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (ppv) *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, CLSID_Greathelm)) return CLASS_E_CLASSNOTAVAILABLE;
    ClassFactory* f = new(std::nothrow) ClassFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

extern "C" DLL_EXPORT HRESULT WINAPI DllCanUnloadNow(void) {
    return (g_objCount.load(std::memory_order_relaxed) == 0 && g_lockCount.load(std::memory_order_relaxed) == 0) ? S_OK : S_FALSE;
}

static HRESULT RegWriteStr(HKEY root, const wchar_t* subkey, const wchar_t* name, const wchar_t* value) {
    HKEY k = nullptr;
    LONG rc = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) return HRESULT_FROM_WIN32(rc);
    rc = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value, (DWORD)((wcslen(value)+1) * sizeof(wchar_t)));
    RegCloseKey(k);

    return HRESULT_FROM_WIN32(rc == ERROR_SUCCESS ? ERROR_SUCCESS : rc);
}

static std::wstring GuidToBracedString(const CLSID& clsid) {
    wchar_t buf[64] = {};
    StringFromGUID2(clsid, buf, 64);
    return std::wstring(buf);
}

extern "C" DLL_EXPORT HRESULT WINAPI DllRegisterServer(void) {
    wchar_t path[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_hMod, path, MAX_PATH)) return HRESULT_FROM_WIN32(GetLastError());

    const std::wstring clsid = GuidToBracedString(CLSID_Greathelm);
    const std::wstring keyClsid  = L"CLSID\\" + clsid;
    const std::wstring keyInproc = keyClsid + L"\\InprocServer32";

    HRESULT hr = RegWriteStr(HKEY_CLASSES_ROOT, keyClsid.c_str(), nullptr, L"Greathelm AMSI Provider");
    if (FAILED(hr)) return hr;

    hr = RegWriteStr(HKEY_CLASSES_ROOT, keyInproc.c_str(), nullptr, path);
    if (FAILED(hr)) return hr;

    hr = RegWriteStr(HKEY_CLASSES_ROOT, keyInproc.c_str(), L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

    const wchar_t* AMSI_BASE = L"SOFTWARE\\Microsoft\\AMSI";
    const std::wstring keyProv  = std::wstring(AMSI_BASE) + L"\\Providers\\"  + clsid;
    const std::wstring keyProv2 = std::wstring(AMSI_BASE) + L"\\Providers2\\" + clsid;

    hr = RegWriteStr(HKEY_LOCAL_MACHINE, keyProv.c_str(), nullptr, L"Greathelm");
    if (FAILED(hr)) return hr;

    hr = RegWriteStr(HKEY_LOCAL_MACHINE, keyProv2.c_str(), nullptr, L"Greathelm");
    if (FAILED(hr)) return hr;
    return S_OK;
}

extern "C" DLL_EXPORT HRESULT WINAPI DllUnregisterServer(void) {
    const std::wstring clsid = GuidToBracedString(CLSID_Greathelm);
    const wchar_t* AMSI_BASE = L"SOFTWARE\\Microsoft\\AMSI";

    const std::wstring keyProv  = std::wstring(AMSI_BASE) + L"\\Providers\\"  + clsid;
    const std::wstring keyProv2 = std::wstring(AMSI_BASE) + L"\\Providers2\\" + clsid;

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyProv.c_str());
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyProv2.c_str());

    const std::wstring keyInproc  = L"CLSID\\" + clsid + L"\\InprocServer32";
    const std::wstring keyClsid   = L"CLSID\\" + clsid;

    RegDeleteKeyW(HKEY_CLASSES_ROOT, keyInproc.c_str());
    RegDeleteKeyW(HKEY_CLASSES_ROOT, keyClsid.c_str());
    return S_OK;
}
