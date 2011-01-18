#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  if (argc<2){
    printf("Make sure to use 2 arguments");
    exit(1);
  }
  char temp[50];
  //temp = argv[1];
  strcpy(temp, argv[1]);
  printf("%n", &temp);
}
