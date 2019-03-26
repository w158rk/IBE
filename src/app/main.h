#ifndef MAIN_H
#define MAIN_H

#include"bf_4_1.h"


#define SIZE 100
#define RBITS 160
#define QBITS 512
#define BASE 16
#define BUFF_SIZE 500

int readFromFile(char* dest, const char* filename) {
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
    memset(dest, '\0', BUFF_SIZE);
    fread(dest,length,1,fp);
    fclose(fp);
    return length;
    // return the value
}

#endif