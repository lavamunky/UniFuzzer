#define BUFFERSIZE 10
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	char buffer[BUFFERSIZE];
        printf("Path is :%s", getenv("PATH"));
	strcpy(buffer, getenv("USERNAME"));
	printf("USERNAME is:%s\n", buffer);
}
