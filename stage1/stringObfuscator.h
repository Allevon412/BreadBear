#pragma once
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


char * stringDeobfuscator(char encrypted[], int size);
char* xordecrypt(char* encrypted, char* key, int size, int keysize);
char* xorencrypt(char* message, char* key);