#ifndef MAIN_H
#define MAIN_H

#include"bf_4_1.h"


#define SIZE 100
#define RBITS 160
#define QBITS 512
#define BASE 16

int readFromFile(char** dest, const char* filename) {
    FILE *fp;
    // open the file
    if((fp=fopen(filename,"r"))==NULL)
    {
        printf("open file %s error.\n",filename);
        return -1;
    }
    // get the file length
    int length;
    fseek(fp,0,SEEK_END);
    length=ftell(fp);
    fseek(fp,0,SEEK_SET);

    // read the whole file
    char* str = (char*) malloc(length+1);
    fread(str,length,1,fp);
    *(str+length)='\0';
    fclose(fp);

    // return the value
    *dest = str;
}

#endif