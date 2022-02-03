#include "ModuleStomp.h"

/*
Unfortunately, module stomping does not work properly. When I try to load a PE ontop of a DLL module loaded in memory it breaks. There could be numerous reasons why this does not work. It's not too important b/c allocating the memory manually still works.
*/


BOOL InjectSCModuleStomp(DWORD_PTR baseAddr, SIZE_T imageSize, DWORD_PTR* outPtr) {
	
	//library strings
	//WCHAR sLib[] = { 'w','i','n','d','o','w','s','.','s','t','o','r','a','g','e','.','d','l','l', 0x0 };
	//WCHAR strK32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };
	
	//function string
	//char strVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0x0 };

	//function pointer
	//t_VirtualProtect pVirtualProtect = (t_VirtualProtect)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strVirtualProtect);

	//HMODULE hVictimLib = customLoadLibrary(sLib);

	//SIZE_T storageImageSize = getImageSize((DWORD_PTR)hVictimLib);

	//if (imageSize > storageImageSize) {
	//	exit(-10);
	//}

	//DWORD oldprotect = 0;
	//DWORD_PTR ptr = (DWORD_PTR)hVictimLib + 2 * 4096 + 12;
	//pVirtualProtect(ptr, imageSize, PAGE_EXECUTE_READWRITE, &oldprotect);

	//DWORD_PTR ptr = VirtualAlloc(NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//*outPtr = ptr;

	//return TRUE;
}