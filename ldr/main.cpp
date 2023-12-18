#include <string>
#include <fstream> 
#include <random>
#include "Main.h"
#include "Security.h"
#include "gdrv_bytes.h"
#include "drv_bytes.h"
#include "lazy.h"
#include "antidebug.h"
#include "manualmap.h"

#define BREAK_WITH_ERROR( e ) { ShowWindow(GetConsoleWindow(), SW_SHOW); printf( strenc("[-] %s. Error=%d"), e, GetLastError() ); system(strenc("pause")); break; }
#define WIN32_LEAN_AND_MEAN

#pragma comment(lib, "ntdll.lib")

void CreateConsole();
void SetWorkingDir();
const wchar_t* gdrv_path = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";
const wchar_t* vmulti_path = L"C:\\Windows\\System32\\Drivers\\vmulti64.sys";

ifstream in("hwid.txt");
DWORD FindProcessId(const char* processname);
injec* inject;
char inj;

void RunAndCreateUpdateBatch()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	char fname[30];
	char dir[64];
	char drive[3];
	char ext[5];
	_splitpath(buffer, drive, dir, fname, ext);


	std::string batText = strenc(":1\nerase "); batText += fname;
	batText += strenc(".exe\nif exist "); batText += fname;
	batText += strenc(".exe Goto 1\nerase _tmp.cmd");

	FILE* f = fopen("_tmp.cmd", "wb");
	fwrite(batText.c_str(), 1, strlen(batText.c_str()), f);
	fclose(f);

	ShellExecute(NULL, strenc("open"), strenc("_tmp.cmd"), NULL, NULL, NULL);
}

HRESULT DownloadStatus::OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR wszStatusText)
{
	printf(".");
	return S_OK;
}

bool DropDriverFromBytes(const wchar_t* path) //gdrv
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileW(path, GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, shell_mapper, sizeof(shell_mapper), &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
}

bool DropDriverFromBytes2(const wchar_t* path) //vmulti64
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileW(path, GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, drv, sizeof(drv), &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
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
}*/ //bsod x32

bool HstCheck()
{
	ifstream file(strenc("C://Windows//System32/drivers//etc//hosts")); //opens hosts
	string s;
	char c;

	while (!file.eof())
	{
		file.get(c);
		s.push_back(c);
	}

	file.close();

	int pos = s.find(strenc("insage.ru")); //founding for string

	if (pos == -1) //not found
	{
		return true;
	}
	else
	{
		const char* str2 = strenc("hosts modificated!\n\n"); //found
		printf(str2);
		Sleep(2000);
		//asmbs(); //bsod
		exit(-1);
		//asmbs(); //bsod
		return false;
	}
}

void RandomNameString()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> distr(0, 51);
	std::string name = "";
	char alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	for (int i = 0; i < 15; ++i)
	{
		name = name + alphabet[distr(mt)];
		SetConsoleTitleA(name.c_str());
	}

}

DWORD get_pid(char* ProcName)
{
	PROCESSENTRY32 lppe;
	long PID = 0, Result = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnap)
	{
		lppe.dwSize = sizeof(PROCESSENTRY32);
		Result = Process32First(hSnap, &lppe);
		while (Result)
		{
			if (strcmp(lppe.szExeFile, ProcName) == NULL)
			{
				PID = lppe.th32ProcessID;
				break;
			}
			Result = Process32Next(hSnap, &lppe);
		}
		CloseHandle(hSnap);
	}
	return PID;
}

int _stdcall  WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) //console main() || windows application WinMain(---)
{
	if (IsAdministrator() == FALSE)
	{
		MessageBox(NULL, "Open As Administrator", "INSAGE.RU LOADER", MB_OK);
		exit(-1);
	}
	CreateConsole();
	LI_FN(CreateThread)(nullptr, 0, Thread, nullptr, 0, nullptr);
	if (IsVirtualBox() == FALSE && IsSandboxie() == FALSE && IsVM() == FALSE)
	{
		//	HideFromDebugger();
		//	AntiAttach();
		HstCheck();
		bool exit_update = false;
#if ENABLE_LICENSING == 1
		{
			CLicense License;

			string OldSerial = License.GetOldSerial();
			string NewSerial = License.GetSerial();
			string ReLicData = OldSerial + "|" + NewSerial;

			ReLicData = base64_encode(ReLicData.c_str(), ReLicData.size());

			const char* news = strenc("Checking your subscription... \n\n");

			printf(news, NewSerial.c_str());

			string path = PATH;
			path.append(strenc("rebind.php?data="));

			string ReLicenseUrl = path + ReLicData;
			string ServerRequest = License.GetUrlData(ReLicenseUrl);

			if (ServerRequest == strenc("error: 1"))
			{
				const char* str = strenc("Subscription found!\n\n");
				printf(str);
			}
			else if (ServerRequest == strenc("error: 2"))
			{
				const char* str = strenc("Subscription has expired! :<\n");
				printf(str);
				exit_update = true;
				ofstream out;
				out.open("hwid.txt");
				out << strenc("Your HWID: ") << NewSerial.c_str() << '\n';
				out.close();
			}
			else if (ServerRequest == strenc("error: 3"))
			{
				const char* str = strenc("Subscription not found! :<\n");
				printf(str);
				exit_update = true;
				ofstream out;
				out.open("hwid.txt");
				out << strenc("Your HWID: ") << NewSerial.c_str() << '\n';
				out.close();
			}
			else if (ServerRequest == strenc("success"))
			{
				const char* str = strenc("Subscription activated! :>\n");
				printf(str);
			}

			if (License.CheckLicense() && !exit_update)
			{
				printf(strenc("Subscription: %s days :>\n"), License.GetUserDayCount().c_str());

				if (License.CheckVersion())
				{
					License.ShowUpdateUrl();
				}
			}
			else
			{
				printf(strenc("Subscription: ? :<\n"));
				exit_update = true;
				ofstream out;
				out.open("hwid.txt");
				out << strenc("Your HWID: ") << NewSerial.c_str() << '\n';
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
		ShowWindow(GetConsoleWindow(), SW_SHOW);
		SetWorkingDir();

		do
		{
			
			//DropDriverFromBytes2(vmulti_path);
			//SetFileAttributes("C:\\Windows\\System32\\Drivers\\vmulti64.sys", FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ENCRYPTED);
			//system("sc create vmulti64 binPath= C:\\Windows\\System32\\Drivers\\vmulti64.sys type=kernel");
			//system("cls");
			//system("sc start vmulti64");
			//system("cls");
			SetConsoleOutputCP(CP_UTF8);
			printf("   ██╗███╗  ██╗ ██████╗ █████╗  ██████╗ ███████╗   ██████╗ ██╗   ██╗\n");
			printf("   ██║████╗ ██║██╔════╝██╔══██╗██╔════╝ ██╔════╝   ██╔══██╗██║   ██║\n");
			printf("   ██║██╔██╗██║╚█████╗░███████║██║  ██╗ █████╗     ██████╔╝██║   ██║\n");
			printf("   ██║██║╚████║ ╚═══██╗██╔══██║██║  ╚██╗██╔══╝     ██╔══██╗██║   ██║\n");
			printf("   ██║██║ ╚███║██████╔╝██║  ██║╚██████╔╝███████╗██╗██║  ██║╚██████╔╝\n");
			printf("   ╚═╝╚═╝  ╚══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝\n");

			/*DWORD pid = 0;
		    pid = get_pid((char*)"GenshinImpact.exe");
		    typedef unsigned char       BYTE;
		    inject->manualmap(pid, (PBYTE)rawData); */ // BYTE name[] { ... }; //injection part//

			//printf("Log::injected! Press any key to uninject...");
			//system("pause");
			//system("cls");


		} while (0);
		{
			//system("sc stop vmulti64");
			//system("cls");
			//system("sc delete vmulti64");
			//system("cls");
			Sleep(1000);
			//remove("C:\\Windows\\System32\\Drivers\\vmulti64.sys");
			//system("cls");
			//printf("Log::successfully uninjected the cheat...");
			Sleep(5000);
		}


		return 0;
	}
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

	RegCreateKeyEx(HKEY_CURRENT_USER, strenc("Software\\RWindowsNoEditor1"), 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	RegSetValueEx(hKey, "path", 0, REG_SZ, (LPBYTE)&szPath, strlen(szPath));
}

void CreateConsole()
{
	AllocConsole();
	freopen(strenc("CONOUT$"), strenc("wt"), stdout);
	freopen(strenc("CONIN$"), strenc("rt"), stdin);
	RandomNameString();
	system(strenc("color 5"));
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
