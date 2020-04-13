#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <iostream>

int main(int argc, char *argv[]) {
    
	//读文件，写入数组
	FILE *inputfile = NULL;
	int i = 0;
	
	inputfile = fopen(argv[1], "r");
	if (inputfile == NULL){
		printf("Error opening file.");
	} else {
		char ch;
		while ((ch=fgetc(inputfile)) != EOF){
			i = i + 1;
			printf("%c",ch);
		}
		fclose(inputfile);
	}
	
	//根据文件长度，分配堆内存
	char *buf = new char [i*20*sizeof(char)*1024];
	//char *buf = malloc(i*20*sizeof(char)*1024);
	buf[0]='a';
	delete[] buf;
	//free(buf);
	
	return 0;
}
