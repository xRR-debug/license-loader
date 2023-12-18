#pragma once

#include "main.h"
#include "encrypt.h"
#include <WinInet.h>
#include <WbemIdl.h>
#include <iphlpapi.h>
#include <string>
#include <sstream>
#include <string>
#include <vector>


using namespace std;

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi")

#define ENABLE_LICENSING 1

//[enc_string_enable /]
#define HOST			strenc("insage.ru")
#define HOST2			strenc("insage.xyz")
#define PATH			strenc("/panel/")

#define HOST_GATE		strenc("gate.php?serial=")
#define HOST_KEY_GATE	strenc("license-success-ok-")

#define HOST_CHECK		strenc("check.php?serial=")
#define HOST_KEY_CHECK	strenc("2D262FF36ED16964-")

#define CHEAT_VERSION	strenc("2")

class CLicense
{
private:
	//[swap_lines]
	string	StringToHex(const string input);
	string	GetHashText(const void* data, const size_t data_size);

	string	GetHwUID();
	string	GetMacID();
	DWORD	GetVolumeID();
	string	GetCompUserName(bool User);
	string	GetSerialKey();
	string	GetHashSerialKey();
	//[/swap_lines]
public:
	//[swap_lines]
	string	GetUrlData(string url);
	string	GetOldSerial();
	string	GetSerial();
	string	GetSerial64();
	string	GetUserDayCount();
	string  GetIP(string hostname);
	bool	CheckLicenseURL(string URL, string GATE, string KEY);
	bool	CheckLicense();
	bool	CheckVersion();
	void	ShowUpdateUrl();
	//[/swap_lines]
};

string base64_encode(char const* bytes_to_encode, unsigned int in_len);
