#include "manualmap.h"
#include "xorstr.h"
#include <stdio.h>
#include <string>
#include <iostream>
#include "nt.h"

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
#pragma code_seg(".mdata")

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
	{
		pData->hMod = (HINSTANCE)0x121314;
		return;
	}


	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	//Relocate Image
	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		auto* pRelocDir = (IMAGE_DATA_DIRECTORY*)(&pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (!pRelocDir->Size)
		{
			pData->hMod = (HINSTANCE)0x646566;
			return;
		}

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	//Remove strings from the import directory
	DWORD importSize = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (importSize)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	//Fix tls
	DWORD tlsSize = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (tlsSize)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);

		pTLS->AddressOfCallBacks = 0;
		pTLS->AddressOfIndex = 0;
		pTLS->EndAddressOfRawData = 0;
		pTLS->SizeOfZeroFill = 0;
		pTLS->StartAddressOfRawData = 0;
		pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
		pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}


LPVOID  _ntAllocateVirtualMemory(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {

	LPVOID ret = lpAddress;

	auto status = nt->pNtAllocateVirtualMemory(hProcess, &ret, 0, &dwSize, flAllocationType, flProtect);

	if (NT_SUCCESS(status))//STATUS_SUCCESS
		return ret;

	return NULL;

}

HANDLE _ntCreateThreadEx(HANDLE  hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
	HANDLE threadHandle;

	auto status = nt->pNtCreateThreadEx(&threadHandle, 0x1FFFFF, NULL, hProcess, lpStartAddress, lpParameter, 0x00000004, NULL, NULL, NULL, NULL);

	if (status == 0x00000000) {
		return threadHandle;
	}

	return 0;
}

HANDLE _ntOpenProcess(DWORD pid) {

	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE handle;
	CLIENT_ID clientId;

	clientId.UniqueThread = NULL;
	clientId.UniqueProcess = (PVOID)(pid);
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

	auto status = nt->pZwOpenProcess(&handle,
		PROCESS_ALL_ACCESS,
		&objectAttributes,
		&clientId);

	if (!handle || !NT_SUCCESS(status)) {
		return 0;
	}
	return handle;
}

BOOL _ntWriteVirtualMemory(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten) {

	auto status = nt->pNtWriteVirtualMemory(hProcess, lpBaseAddress, (PVOID)lpBuffer, nSize, lpNumberOfBytesWritten);

	if (!NT_SUCCESS(status))
		return FALSE;

	return TRUE;
}

bool ManualMap(HANDLE hProc, BYTE* pSrcData) // /EHa /EHc x64 /Zc
{

	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	// Checking for file is valid
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
	{
		printf(xorstr_("Invalid file.\n"));
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	// Checking for file architecture
	if (pOldFileHeader->Machine != CURRENT_ARCH)
	{
		printf(xorstr_("Invalid architecture.\n"));
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	printf(xorstr_("File ok.\n"));

	// Allocating memory for the DLL
	pTargetBase = reinterpret_cast<BYTE*>(LI_FN(VirtualAllocEx)(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		printf(xorstr_("Target process memory allocation failed (ex) 0x%X.\n"), GetLastError());
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LI_FN(LoadLibraryA).forwarded_safe_cached();
	data.pGetProcAddress = LI_FN(GetProcAddress).forwarded_safe_cached();
	data.pbase = pTargetBase;

	// Copying the headers to target process
	if (!LI_FN(WriteProcessMemory)(hProc, pTargetBase, pSrcData, 0x1000, nullptr))
	{ 
		printf(xorstr_("Can't write file header 0x%X.\n"), GetLastError());
		LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	// Copying sections of the dll to the target process
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData)
		{
			if (!LI_FN(WriteProcessMemory)(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				printf(xorstr_("Can't map sections: 0x%x.\n"), GetLastError());
				LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
				memset(pSrcData, 0, sizeof(pSrcData));
				return false;
			}
		}
	}

	// Allocating memory for loader params
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(LI_FN(VirtualAllocEx)(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc)
	{
		printf(xorstr_("Target process mapping allocation failed (ex) 0x%X.\n"), GetLastError());
		LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	if (!LI_FN(WriteProcessMemory)(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		printf(xorstr_("Can't write mapping 0x%X.\n"), GetLastError());
		LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
		LI_FN(VirtualFreeEx)(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		delete[] pSrcData;
		return false;
	}

	// Allocating memory for the loader code
	void* pShellcode = LI_FN(VirtualAllocEx)(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf(xorstr_("Memory shellcode allocation failed (ex) 0x%X.\n"), GetLastError());
		LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
		LI_FN(VirtualFreeEx)(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	//Write loader code
	if (!LI_FN(WriteProcessMemory)(hProc, pShellcode, Shellcode, 0x1000, nullptr))
	{
		printf(xorstr_("Can't write shellcode 0x%X.\n"), GetLastError());
		LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
		LI_FN(VirtualFreeEx)(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		LI_FN(VirtualFreeEx)(hProc, pShellcode, 0, MEM_RELEASE);
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}

	printf(xorstr_("Data allocated.\n"));

#ifdef _DEBUG
	printf(xorstr_("My shellcode pointer %p.\n"), Shellcode);
	printf(xorstr_("Target point %p.\n"), pShellcode);
	system(xorstr_("pause"));
#endif

	HANDLE hThread = LI_FN(CreateRemoteThread)(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread)
	{
		printf(xorstr_("Thread creation failed 0x%X.\n"), GetLastError());
		LI_FN(VirtualFreeEx)(hProc, pTargetBase, 0, MEM_RELEASE);
		LI_FN(VirtualFreeEx)(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		LI_FN(VirtualFreeEx)(hProc, pShellcode, 0, MEM_RELEASE);
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}
	LI_FN(CloseHandle)(hThread);
	memset(pSrcData, 0, sizeof(pSrcData));

	printf(xorstr_("Thread created at: %p, waiting for return...\n"), pShellcode);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		DWORD exitcode = 0;
		LI_FN(GetExitCodeProcess)(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE)
		{
			printf(xorstr_("Process crashed, exit code: %d.\n"), exitcode);
			memset(pSrcData, 0, sizeof(pSrcData));
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		LI_FN(ReadProcessMemory)(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x121314)
		{
			printf(xorstr_("Wrong mapping pointer.\n"));
			memset(pSrcData, 0, sizeof(pSrcData));
			return false;
		}
		else if (hCheck == (HINSTANCE)0x646566)
		{
			printf(xorstr_("Wrong directory base relocation.\n"));
			memset(pSrcData, 0, sizeof(pSrcData));
			return false;
		}

		LI_FN(Sleep).safe()(10);
	}

	BYTE* emptyBuffer2 = (BYTE*)malloc(1024 * 1024);
	if (emptyBuffer2 == nullptr)
	{
		printf(xorstr_("Unable to allocate memory\n"));
		memset(pSrcData, 0, sizeof(pSrcData));
		return false;
	}
	memset(emptyBuffer2, 0, 1024 * 1024);

	//Protection
	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (strcmp((char*)pSectionHeader->Name, xorstr_(".pdata")) == 0 ||
				strcmp((char*)pSectionHeader->Name, xorstr_(".rsrc")) == 0 ||
				strcmp((char*)pSectionHeader->Name, xorstr_(".reloc")) == 0)
				//  || strcmp((char*)pSectionHeader->Name, xorstr_(".rdata")) == 0 )
			{
				printf(xorstr_("Removed %s section header.\n"), pSectionHeader->Name);
				if (!LI_FN(WriteProcessMemory)(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer2, pSectionHeader->SizeOfRawData, nullptr))
				{
					printf(xorstr_("Can't clear section %s: 0x%x.\n"), pSectionHeader->Name, GetLastError());
				}
			}
		}
	}

	DWORD old = 0;
	LI_FN(VirtualFreeEx)(hProc, pShellcode, 0, MEM_RELEASE);
	LI_FN(VirtualFreeEx)(hProc, MappingDataAlloc, 0, MEM_RELEASE);
	memset(pSrcData, 0, sizeof(pSrcData));

	LI_FN(VirtualProtectEx)(hProc, pTargetBase, pSectionHeader->VirtualAddress, PAGE_READONLY, &old);

	LI_FN(Sleep).safe()(500);
	CloseHandle(hProc);
	return true;
}
