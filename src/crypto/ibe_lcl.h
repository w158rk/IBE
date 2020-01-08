#ifndef IBE_LCL_H 
#define IBE_LCL_H 

#define MPK_LEN     239
#define SK_LEN      381

typedef unsigned long size_t;
char *ibe_malloc_char(size_t size);
void ibe_free_char(char *);

#endif