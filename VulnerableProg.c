#define BUFFERSIZE 1024
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char buffer[BUFFERSIZE];
	if (argc>1)
	{
      		strcpy(buffer, argv[1]);
		printf("%s\n", buffer);
	}
	if (argc>2)
	{
		printf("more than 1 arguement!");
		strcpy(buffer, argv[2]);
		printf("%s\n", buffer);
	}
}
