#include "DynamicFunctionResolvers.h"

typedef HMODULE(WINAPI* LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = NULL;

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (sModuleName == NULL)
		return (HMODULE)(ProcEnvBlk->ImageBase);

	PEB_LDR_DATA* Ldr = ProcEnvBlk->LoaderData;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
		pListEntry != ModuleList;	    	// walk all list entries
		pListEntry = pListEntry->Flink) {

		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}

	// otherwise:
	return NULL;

}

//custom implmementation of getProcAddress by manually looking up function names / pointers using the PE Header structure.
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName) {

	//base address of the dll we want to extract our function address from.
	char* pBaseAddr = (char*)hMod;

	// get pointers to main headers/structures
	//Base Address of the PE Dos Header.
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	//parse DosHeader until e_lfanew field which holds the RVA of the NTHeader 
	//(to get the actual address remember that you need to add the base address to the RVA since its relative. base = 1000 rva = 300 address == 1300).
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	//once we have the address to the NTHeader structure we extract the OptionalHeader Structure.
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	//Then we extract the DataDirectory from the optionalHeader structure.
	IMAGE_DATA_DIRECTORY* pDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	//Then we extract the virtualAddress of the export Directory table from the DataDirectory structure to get the actual address of the exportDirectory address.
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void* pProcAddr = NULL;

	// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD)sProcName & 0xFFFF;	// convert to WORD
		DWORD Base = pExportDirAddr->Base;			// first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
	}
	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

			if (strcmp(sProcName, sTmpFuncName) == 0) {
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}

	// check if found VA is forwarded to external library.function
	if ((char*)pProcAddr >= (char*)pExportDirAddr &&
		(char*)pProcAddr < (char*)(pExportDirAddr + pDataDir->Size)) {

		char* sFwdDLL = _strdup((char*)pProcAddr); 	// get a copy of library.function string
		if (!sFwdDLL) return NULL;

		// get external function name
		char* sFwdFunction = strchr(sFwdDLL, '.');
		*sFwdFunction = 0;					// set trailing null byte for external library name -> library\x0function
		sFwdFunction++;						// shift a pointer to the beginning of function name
		unsigned char strLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0x0 };
		WCHAR Kernel32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };

		// resolve LoadLibrary function pointer, keep it as global variable
		if (pLoadLibraryA == NULL) {
			pLoadLibraryA = (LoadLibrary_t)hlpGetProcAddress(hlpGetModuleHandle(Kernel32dll), strLoadLibraryA);
			if (pLoadLibraryA == NULL) return NULL;
		}

		// load the external library
		HMODULE hFwd = pLoadLibraryA(sFwdDLL);
		free(sFwdDLL);							// release the allocated memory for lib.func string copy
		if (!hFwd) return NULL;

		// get the address of function the original call is forwarded to
		pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
	}

	return (FARPROC)pProcAddr;
}
