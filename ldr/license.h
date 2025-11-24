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
#include "lazy.h"
#include "dynamic_xorstr.h"

using namespace std;

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi")

#define ENABLE_LICENSING 1

#define HOST			_xor_("insage.ru").c_str()
#define HOST2			_xor_("insage.xyz").c_str()
#define PATH			_xor_("/panel/").c_str()

#define HOST_GATE		_xor_("gate.php?serial=").c_str()
#define HOST_KEY_GATE	_xor_("license-success-ok-").c_str()
						
#define HOST_CHECK		_xor_("check.php?serial=").c_str()
#define HOST_KEY_CHECK	_xor_("B101651E4A421CB062E37C9FBBC5D96DCA3E5977B62A03644333193E9FAA58C4").c_str() //sha 256
						
#define CHEAT_VERSION	_xor_("4").c_str()

class CLicense
{
private:
	string	StringToHex(const string input);
	string	GetHashText(const void* data, const size_t data_size);

	string	GetHwUID();
	string	GetMacID();
	DWORD	GetVolumeID();
	string	GetCompUserName(bool User);
	string	GetSerialKey();
	string	GetHashSerialKey();
public:
	string	PostUrlData(string url);
	string	GetUrlData(string url);
	string	GetOldSerial();
	string	GetSerial();
	string	GetSerial64();
	string	GetUserDayCount();
	string  GetIP(string hostname);
	bool	CheckLicenseURL(string URL, string GATE, string KEY);
	bool	CheckLicense();
	bool	CheckVersion();
	std::string GetActivatedKey(char inuserkey[16]);
	std::string GetVersion();
	void	ShowUpdateUrl();
};

string base64_encode(char const* bytes_to_encode, unsigned int in_len);
