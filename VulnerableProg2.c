#define BUFFERSIZE 10
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char buffer[BUFFERSIZE];
	char buffer2[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	strcpy(buffer, buffer2);
	printf("%s\n", buffer);

}
