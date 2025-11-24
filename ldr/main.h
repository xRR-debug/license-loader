#pragma once
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <Wincrypt.h>
#include <Shellapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <urlmon.h>
#include <Winsock.h>
#include "aes.h"


#pragma comment(lib ,"Advapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Ws2_32")

using namespace std;

#include "license.h"

class DownloadStatus : public IBindStatusCallback
{
public:

    STDMETHOD(OnStartBinding)(DWORD dwReserved, IBinding __RPC_FAR* pib)
    {
        return E_NOTIMPL;
    }
    STDMETHOD(GetPriority)(LONG __RPC_FAR* pnPriority)
    {
        return E_NOTIMPL;
    }
    STDMETHOD(OnLowResource)(DWORD reserved)
    {
        return E_NOTIMPL;
    }
    STDMETHOD(OnProgress)(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR wszStatusText);
    STDMETHOD(OnStopBinding)(HRESULT hresult, LPCWSTR szError)
    {
        return E_NOTIMPL;
    }
    STDMETHOD(GetBindInfo)(DWORD __RPC_FAR* grfBINDF, BINDINFO __RPC_FAR* pbindinfo)
    {
        return E_NOTIMPL;
    }
    STDMETHOD(OnDataAvailable)(DWORD grfBSCF, DWORD dwSize, FORMATETC __RPC_FAR* pformatetc, STGMEDIUM __RPC_FAR* pstgmed)
    {
        return E_NOTIMPL;
    }
    STDMETHOD(OnObjectAvailable)(REFIID riid, IUnknown __RPC_FAR* punk)
    {
        return E_NOTIMPL;
    }
    STDMETHOD_(ULONG, AddRef)()
    {
        return 0;
    }
    STDMETHOD_(ULONG, Release)()
    {
        return 0;
    }
    STDMETHOD(QueryInterface)(REFIID riid, void __RPC_FAR* __RPC_FAR* ppvObject)
    {
        return E_NOTIMPL;
    }
};
