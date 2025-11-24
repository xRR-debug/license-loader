#include <string>
#include <fstream> 
#include <random>
#include "main.h"
#include "gdrv_bytes.h"
#include "drv_bytes.h"
#include "lazy.h"
#include "antidebug.h"
#include "manualmap.h"
#include "VMProtectSDK.h"
#include "xorstr.h"
#include "dynamic_xorstr.h"

#define BREAK_WITH_ERROR( e ) { ShowWindow(GetConsoleWindow(), SW_SHOW); printf( xorstr_("[-] %s. Error=%d"), e, GetLastError() ); system(xorstr_("pause")); break; }
#define WIN32_LEAN_AND_MEAN

#pragma comment(lib, "ntdll.lib")

struct AES_ctx ctx;

void CreateConsole();
void SetWorkingDir();
void encrypt();
void decrypt();

const wchar_t* gdrv_path = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";
const wchar_t* vmulti_path = L"C:\\Windows\\System32\\Drivers\\vmulti64.sys";

ifstream in(xorstr_("hwid.txt"));
DWORD FindProcessId(const char* processname);
uint32_t FindProcess(const std::string& Name);


int argc;
char** argv;

void RunAndCreateUpdateBatch()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	char fname[30];
	char dir[64];
	char drive[3];
	char ext[5];
	_splitpath(buffer, drive, dir, fname, ext);


	std::string batText = xorstr_(":1\nerase "); batText += fname;
	batText += xorstr_(".exe\nif exist "); batText += fname;
	batText += xorstr_(".exe Goto 1\nerase _tmp.cmd");

	FILE* f = fopen("_tmp.cmd", "wb");
	fwrite(batText.c_str(), 1, strlen(batText.c_str()), f);
	fclose(f);

	ShellExecute(NULL, xorstr_("open"), xorstr_("_tmp.cmd"), NULL, NULL, NULL);
}

HRESULT DownloadStatus::OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR wszStatusText)
{
	printf(xorstr_("."));
	return S_OK;
}

bool DropFileFromBytes(const wchar_t* path)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = LI_FN(CreateFileW).safe()(path, GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = LI_FN(WriteFile).safe()(h_file, shell_mapper, sizeof(shell_mapper), &byte, nullptr);
	LI_FN(CloseHandle)(h_file);

	if (!b_status)
		return false;

	return true;
}

bool DropFileFromBytes2(const wchar_t* path)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = LI_FN(CreateFileW).safe()(path, GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = LI_FN(WriteFile).safe()(h_file, rawData, sizeof(rawData), &byte, nullptr);
	LI_FN(CloseHandle)(h_file);

	if (!b_status)
		return false;

	return true;
}

void RandomNameString()
{
	VMP_VIR("RandomStringName");

	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> distr(0, 51);
	std::string name = "";
	char alpha[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	for (int i = 0; i < 15; ++i)
	{
		name = name + alpha[distr(mt)];
		LI_FN(SetConsoleTitleA)(name.c_str());
	}

	VMP_END;
}

void RandomNameStringThread()
{
	srand(time(0)); 
	while (1) 
	{
		int random1 = rand() % 999999 + 100000; 
		int random2 = rand() % 52999 + 1510; 
		int random3 = rand() % 614613455 + 513;
		int random4 = rand() % 613463176 + 3146662;
		std::string title; 
		title.append(std::to_string(random1)); 
		title.append(std::to_string(random2)); 
		title.append(std::to_string(random3));
		title.append(std::to_string(random4));
		LI_FN(SetConsoleTitleA)(title.c_str());
		LI_FN(Sleep).cached()(500);
	}
}

bool IsCorrectTargetArchitecture(HANDLE hProc) 
{
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) 
	{
		printf(_xor_("Can't confirm target process architecture: 0x%X.\n").c_str(), GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

void Session()
{
	std::this_thread::sleep_for(std::chrono::seconds(40));
	printf(_xor_("\nSession clossed because expired.\n").c_str());
	Shutdown();
}

unsigned char eax[32] = { 0x2b, 0xe7, 0x51, 0x61, 0x82, 0xae, 0xdd, 0xdd, 0xab, 0xc7, 0x51, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x69, 0x77, 0xbc, 0x1c, 0x92, 0x93, 0x94, 0x95, 0x32, 0xbb, 0x6b, 0xfc, 0x88, 0x69, 0x69, 0xbb }; //32
unsigned char dx[32] = "\xd9\x20\x53\xb3\x3a\x3b\xce\x62\x31\x85\x58\x15\x21\x74\x5a\x98\x44\xb3\xbc\x68\x69\xbd\xc1\xf9\xd9\xdf\xcd\x32\x64\x32\x64"; //32

void rainbow_text(std::string text)
{
	HANDLE thisConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	int rainbow[] = { 12, 14, 10, 11, 9, 1, 5, 13 };
	int rainbowID = 0;
	for (int i = 0; i < text.length(); i++)
	{
		SetConsoleTextAttribute(thisConsole, rainbow[rainbowID]);
		std::cout << text[i];
		rainbowID++;
		if (rainbowID == 8) rainbowID = 0;
	}
	SetConsoleTextAttribute(thisConsole, 9);
}

static int _stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) //console main() || windows application WinMain(---)
{
	VMP_ULT("Main");

	if (IsAdministrator() == FALSE)
	{
		LI_FN(MessageBoxA).get()(NULL, _xor_("Open As Administrator.").c_str(), _xor_("[insage.ru] LOADER").c_str(), MB_OK);
		Shutdown();
	}

	CreateConsole();
	encrypt();

	std::thread first_thread(Session);
	first_thread.detach();

	std::thread sec_thread(threadd);
	sec_thread.detach();

	DebugSelf();
	LI_FN(CreateThread)(nullptr, 0, MainThread, nullptr, 0, nullptr);

	//if (IsDebuggersInstalled()) //flags
	//{
	//	printf(xorstr_("\n"));
		//LI_FN(system)(xorstr_("pause"));
		//Shutdown();
	//}

	if (IsVirtualBox() == FALSE && IsSandboxie() == FALSE && IsVM() == FALSE)
	{
		bool exit_update = false;
		std::string ProcessName = argc > 1 ? argv[1] : "";

		HANDLE handle_mutex = LI_FN(OpenMutexA).get()(MUTEX_ALL_ACCESS, 0, _xor_("921A581979DF57F1393B610D90047B5E89760FB240E0E1E05AE75BAC30D5FA35").c_str());
		if (!handle_mutex)
		{
			handle_mutex = LI_FN(CreateMutexA).get()(0, 0, _xor_("921A581979DF57F1393B610D90047B5E89760FB240E0E1E05AE75BAC30D5FA35").c_str());
		}
		else
		{
			return 0;
		}

#if ENABLE_LICENSING == 1
		{
			CLicense License;

			string ipaddr = License.GetIP(HOST);
		
			string OldSerial = License.GetOldSerial();
			string NewSerial = License.GetSerial();
			string ReLicData = OldSerial + "|" + NewSerial;

			ReLicData = base64_encode(ReLicData.c_str(), ReLicData.size());

			const char* news = _xor_("[insage.ru] Checking your subscription... \n\n").c_str();

			printf(news, NewSerial.c_str());

			string path = PATH;
			path.append(_xor_("rebind.php?data="));

			string ReLicenseUrl = path + ReLicData;
			string ServerRequest = License.GetUrlData(ReLicenseUrl);

			if (ServerRequest == _xor_("error: 1").c_str())
			{
				const char* str = _xor_("[success] Subscription found!\n\n").c_str();
				printf(str);
			}
			else if (ServerRequest == _xor_("error: 2").c_str())
			{
				const char* str = _xor_("[error: 2] Subscription has expired! :<\n").c_str();
				printf(str);
				exit_update = true;
				ofstream out;
				out.open(_xor_("hwid.txt"));
				out << _xor_("Your HWID: ") << NewSerial.c_str() << '\n';
				out.close();
			}
			else if (ServerRequest == _xor_("error: 3").c_str())
			{
				const char* str = _xor_("[error: 3] Subscription not found! :<\n").c_str();
				printf(str);
				exit_update = true;
				ofstream out;
				out.open(_xor_("hwid.txt"));
				out << _xor_("Your HWID: ") << NewSerial.c_str() << '\n';
				out.close();
			}
			else if (ServerRequest == _xor_("success").c_str())
			{
				const char* str = _xor_("[success] Subscription activated! :>\n").c_str();
				printf(str);
			}
			if (License.CheckLicense() && !exit_update)
			{
				printf(_xor_("[insage.ru] Subscription: %s days :>\n").c_str(), License.GetUserDayCount().c_str());

				if (License.CheckVersion())
				{
					License.ShowUpdateUrl();
				}
			}
			else
			{
				printf(_xor_("[insage.ru] error: 4\n").c_str()); //bad connection \ no sub\ 
				exit_update = true;
				ofstream out;
				out.open(_xor_("hwid.txt"));
				out << _xor_("Your HWID:") << NewSerial.c_str() << '\n';
				out.close();
			}
		}

		if (exit_update)
		{
			LI_FN(Sleep).cached()(2500);
			return 0;
		}
#endif
		LI_FN(Sleep).cached()(1500);
		ShowWindow(GetConsoleWindow(), SW_SHOW);
		SetWorkingDir();

		VMP_END;

		do
		{
			//DropFileFromBytes2(vmulti_path);
			//SetFileAttributes("C:\\Windows\\System32\\Drivers\\vmulti64.sys", FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ENCRYPTED);
			//system("sc create vmulti64 binPath= C:\\Windows\\System32\\Drivers\\vmulti64.sys type=kernel");
			//system("cls");
			//system("sc start vmulti64");
			//system("cls");
			LI_FN(system)(xorstr_("cls")); \
				rainbow_text(R"(     
                                .__                                                     
                                |__| ____   __________    ____   ____     _______ __ __ 
                                |  |/    \ /  ___\__  \  / ___\_/ __ \    \_  __ |  |  \
                                |  |   |  \\___ \ / __ \/ /_/  \  ___/     |  | \|  |  /
                                |__|___|  /____  (____  \___  / \___  > /\ |__|  |____/ 
                                        \/     \/     \/_____/      \/  \/          
    

)");     
			
			if (!ProcessName.size())
			{
				printf(_xor_("Enter the x64 target process name: ").c_str());
				std::cin >> std::ws;
				getline(std::cin, ProcessName);
			}

			printf(_xor_("Process Name:  '%s'\n").c_str(), ProcessName.data());

			DWORD pid = FindProcess(ProcessName);
			if (pid == 0) {
				printf(_xor_("Process not found\n").c_str());
				LI_FN(system)(xorstr_("pause"));
				return -1;
			}

			printf(_xor_("Process pid: %d\n").c_str(), pid);

			HANDLE hProc = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pid);
			if (!hProc) {
				DWORD Err = GetLastError();
				printf(_xor_("OpenProcess failed: 0x%X\n").c_str(), Err);
				LI_FN(system)(xorstr_("pause"));
				return -2;
			}

			if (!IsCorrectTargetArchitecture(hProc)) {
				printf(_xor_("Invalid Process Architecture.\n").c_str());
				LI_FN(CloseHandle)(hProc);
				LI_FN(system)(xorstr_("pause"));
				return -3;
			}

			decrypt();

			printf(_xor_("Decrypting...\n").c_str());
			printf(_xor_("Mapping...\n").c_str());
			ManualMap(hProc, &rawData[0]); 
			Sleep(2000);
			delete[](char*)sizeof(dx);
            delete[](char*)sizeof(eax);
			//printf("Log::injected! Press any key to uninject...");
			//system("pause");
			//system("cls");

		} while (0);
		{
			//system("sc stop vmulti64");
			//system("cls");
			//system("sc delete vmulti64");
			//system("cls");
			LI_FN(Sleep).cached()(2000);
			//remove("C:\\Windows\\System32\\Drivers\\vmulti64.sys");
			//system("cls");
			//printf("Log::successfully uninjected the cheat...");
			//LI_FN(Sleep).cached()(5000);
			LI_FN(exit).safe()(-1);
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
	LI_FN(lstrcpynA)(buf, FileName, i + 2);
	return buf;
}

void SetWorkingDir()
{
	VMP_ULT("SetWorkingDir");

	TCHAR szFileName[MAX_PATH], szPath[MAX_PATH];
	HKEY hKey;

	LI_FN(GetModuleFileNameA).forwarded_safe_cached()(NULL, szFileName, sizeof(szFileName));
	ExtractFilePath(szFileName, szPath);

	LI_FN(RegCreateKeyExA).forwarded_safe_cached()(HKEY_CURRENT_USER, _xor_("Software\\WindowsNoEditor").c_str(), 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	LI_FN(RegSetValueExA).forwarded_safe_cached()(hKey, _xor_("path").c_str(), 0, REG_SZ, (LPBYTE)&szPath, strlen(szPath));

	VMP_END;
}

void CreateConsole()
{
	LI_FN(AllocConsole)();
	LI_FN(freopen)(xorstr_("CONOUT$"), xorstr_("wt"), stdout);
	LI_FN(freopen)(xorstr_("CONIN$"), xorstr_("rt"), stdin);
	RandomNameString();
	LI_FN(system)(_xor_("color 9").c_str());
	LI_FN(SetConsoleOutputCP)(CP_UTF8);
}

DWORD FindProcessId(const char* processname)
{
	VMP_VIR("FindProcessId");

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD result = 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	hProcessSnap = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	if (!Process32First(hProcessSnap, &pe32))
	{
		LI_FN(CloseHandle)(hProcessSnap);
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

	LI_FN(CloseHandle)(hProcessSnap);

	return result;

	VMP_END;
}

uint32_t FindProcess(const std::string& Name)
{
	PROCESSENTRY32 ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcessSnapshot = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(ProcessSnapshot, &ProcessEntry))
	{
		do
		{
			if (!_stricmp(ProcessEntry.szExeFile, Name.data()))
			{
				LI_FN(CloseHandle)(ProcessSnapshot);
				return ProcessEntry.th32ProcessID;
			}
		} while (Process32Next(ProcessSnapshot, &ProcessEntry));
	}
	LI_FN(CloseHandle)(ProcessSnapshot);
	return FALSE;
}

VMP_ULT("enc-dec")
void encrypt()
{
	AES_init_ctx_iv(&ctx, eax, dx);
	//AES_CTR_xcrypt_buffer(&ctx, rawData, sizeof(rawData));
	AES_CBC_encrypt_buffer(&ctx, rawData, sizeof(rawData));
}

void decrypt()
{
	AES_init_ctx_iv(&ctx, eax, dx);
	//AES_CTR_xcrypt_buffer(&ctx, rawData, sizeof(rawData));
	AES_CBC_decrypt_buffer(&ctx, rawData, sizeof(rawData));
}
VMP_END
