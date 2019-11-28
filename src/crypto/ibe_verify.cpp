#include <crypto.h>
#include <iostream>
#include <ds.h>
#include <string.h>

/* mpk为顶级域的sP */
int run_ibe_verify(struct SignMesg *sig, IBEPublicParameters *mpk, const char *id, size_t id_len)
{
    int rnt = 0;
    if(sig->front!=nullptr)
    {
        run_ibe_verify(sig->front, mpk, sig->front->ID, strlen(sig->front->ID));
        
        IBEPublicParameters verify_mpk = NULL;
        verify_mpk = sig->front->PP;
        char *verify_id;
        verify_id = sig->front->ID;

        char *mes_id;
        mes_id = sig->ID;
        size_t id_len = strlen(mes_id);
        IBEPublicParameters mes_mpk = NULL;
        mes_mpk = sig->PP;
        
        char *data = (char *)malloc(id_len + IBE_MPK_LEN);
        memcpy(data, mes_mpk, IBE_MPK_LEN);
        memcpy(data + IBE_MPK_LEN, mes_id, id_len);

        if(!ibe_verify(data, id_len + IBE_MPK_LEN, sig->sign_data, strlen(sig->sign_data), &verify_mpk, 239, verify_id, strlen(verify_id)))
        {
            fprintf(stderr, "verify error\n");
        } 
    }
    else
    {
        if(!strcmp((char *)mpk, (char *)sig->PP))
        {
            fprintf(stderr, "verify error\n");
            return -1;
        }
    }

    rnt = 1;
    return rnt;
    
}