#define BREAK_WITH_ERROR( e ) { ShowWindow(GetConsoleWindow(), SW_SHOW); printf( "[-] %s. Error=%d", e, GetLastError() ); system("pause"); break; }
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Tlhelp32.h>
#include <shlwapi.h> 
#include <direct.h>
#include <string>
#include <fstream> 
#include "Main.h"
#include <iostream>
#include <dos.h>
#include "Security.h"
//#include "Utils/Lazy.h"

#pragma comment(lib, "ntdll.lib")

void CreateConsole();
void SetWorkingDir();

ifstream in("hwid.txt");
DWORD FindProcessId(const char* processname);

void RunAndCreateUpdateBatch()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	char fname[30];
	char dir[64];
	char drive[3];
	char ext[5];
	_splitpath(buffer, drive, dir, fname, ext);


	std::string batText = ":1\nerase "; batText += fname;
	batText += ".exe\nif exist "; batText += fname;
	batText += ".exe Goto 1\nerase _tmp.cmd";

	FILE* f = fopen("_tmp.cmd", "wb");
	fwrite(batText.c_str(), 1, strlen(batText.c_str()), f);
	fclose(f);

	ShellExecute(NULL, "open", "_tmp.cmd", NULL, NULL, NULL);
}

HRESULT DownloadStatus::OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR wszStatusText)
{
	printf(".");
	return S_OK;
}

/*void asmbs()
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
}*/ //x82 only

bool hst()
{
	ifstream file("C://Windows//System32/drivers//etc//hosts"); //открываем файл hosts
	string s;
	char c;

	while (!file.eof())
	{
		file.get(c);
		s.push_back(c);
	}

	file.close();

	int pos = s.find("insage.ru"); //ищем там эту строку

	if (pos == -1)
	{
		return true;
	}
	else
	{
		const char* str2 = "hosts modificated!\n\n"; //найдено
		printf(str2);
		Sleep(2000);
		//asmbs(); //bsod
		exit(-1);
		//asmbs(); //bsod
		return false;
	}
}

int _stdcall  WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) //console main() || windows application WinMain(---)
{
	/*if (IsAdministrator() == FALSE)
	{

		MessageBox(NULL, "Open As Administrator", "INSAGE.RU LOADER", MB_OK);
		exit(-1);
	}*/
	CreateConsole();
	//LI_FN(CreateThread)(nullptr, 0, Thread, nullptr, 0, nullptr);
	bool exit_update = false;
	//if (IsVMware() == FALSE && IsVirtualBox() == FALSE && IsSandboxie() == FALSE && IsVM() == FALSE && MemoryBreakpointDebuggerCheck() == FALSE && Int2DCheck() == FALSE)
	//{
	//	HideFromDebugger();
	//	AntiAttach();
		//hst();
#if ENABLE_LICENSING == 1
		{
			CLicense License;

			string OldSerial = License.GetOldSerial();
			string NewSerial = License.GetSerial();
			string ReLicData = OldSerial + "|" + NewSerial;

			ReLicData = base64_encode(ReLicData.c_str(), ReLicData.size());

			const char* news = "Checking your subscription... \n\n";

			printf(news, NewSerial.c_str());

			string path = PATH;
			path.append("rebind.php?data=");

			string ReLicenseUrl = path + ReLicData;
			string ServerRequest = License.GetUrlData(ReLicenseUrl);

			if (ServerRequest == "error: 1")
			{
				const char* str = "Subscription found!\n\n";
				printf(str);
			}
			else if (ServerRequest == "error: 2")
			{
				const char* str = "Subscription has expired! :<\n";
				printf(str);
				exit_update = true;
				ofstream out;
				out.open("hwid.txt");
				out << "Your HWID: " << NewSerial.c_str() << '\n';
				out.close();
			}
			else if (ServerRequest == "error: 3")
			{
				const char* str = "Subscription not found! :<\n";
				printf(str);
				exit_update = true;
				ofstream out;
				out.open("hwid.txt");
				out << "Your HWID: " << NewSerial.c_str() << '\n';
				out.close();
			}
			else if (ServerRequest == "success")
			{
				const char* str = "Subscription activated! :>\n";
				printf(str);
			}

			if (License.CheckLicense() && !exit_update)
			{
				printf("Subscription: %s days :>\n", License.GetUserDayCount().c_str());

				if (License.CheckVersion())
				{
					License.ShowUpdateUrl();
				}
			}
			else
			{
				printf("Subscription: ? :<\n");
				exit_update = true;
				ofstream out;
				out.open("hwid.txt");
				out << "Your HWID: " << NewSerial.c_str() << '\n';
				out.close();
			}
		}
	

	if (exit_update)
	{
		Sleep(2500);
		return 0;
	}
#endif

	Sleep(1500);
	/*printf("\n");
	printf("\n");
	printf("\n");
	printf("Loading.\n");
	Sleep(500);
	DoSteam();
	Sleep(8000);
	printf("Run CS:GO and Have Fun!!!!! \n");
	Sleep(1200); */
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	SetWorkingDir();

	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	void* lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	DWORD dwProcessId = 0;
	TOKEN_PRIVILEGES priv = { 0 };
	

	do
	{
		while (!dwProcessId)
		{
			dwProcessId = FindProcessId("csgo.exe");
			Sleep(100);
		}

		while (!(FindWindowA("Valve001", NULL)))
			Sleep(200);

		//[enc_string_enable /]
		//decrypt();
		//lpBuffer = &hdata;
		//dwLength = sizeof(hdata);
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_CREATE_GLOBAL_NAME, &priv.Privileges[0].Luid)) //SE_DEBUG_NAME
				AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

			CloseHandle(hToken);
		}

		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
		if (!hProcess)
			BREAK_WITH_ERROR("Failed to open the target process!");

		//hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
		if (!hModule)
			BREAK_WITH_ERROR("Failed to inject!");

		printf("Log::Injected!");

		WaitForSingleObject(hModule, -1);

	} while (0);

	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}

LPTSTR ExtractFilePath(LPCTSTR FileName, LPTSTR buf)
{
	int i, len = lstrlen(FileName);
	for (i = len - 1; i >= 0; i--) {
		if (FileName[i] == '\\')
			break;
	}
	lstrcpyn(buf, FileName, i + 2);
	return buf;
}

void SetWorkingDir()
{
	TCHAR szFileName[MAX_PATH], szPath[MAX_PATH];
	HKEY hKey;

	GetModuleFileName(NULL, szFileName, sizeof(szFileName));
	ExtractFilePath(szFileName, szPath);

	RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\RWindowsNoEditor1", 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	RegSetValueEx(hKey, "path", 0, REG_SZ, (LPBYTE)&szPath, strlen(szPath));
}

void CreateConsole()
{
	AllocConsole();
	freopen("CONOUT$", "wt", stdout);
	freopen("CONIN$", "rt", stdin);
}

DWORD FindProcessId(const char* processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD result = 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		if (0 == _stricmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}
