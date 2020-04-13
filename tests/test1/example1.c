#include <stdio.h>
#include <stdlib.h>
#include <signal.h>


int fact(int number){//递归函数
	int n = number;
	if (n==1 || n==0)
		return 1;
	return n * fact(n - 1);
}

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
	
	//根据文件长度，确定递归次数
	printf("%d\n", fact(i));
	
	return 0;
}
