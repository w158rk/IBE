#include <crypto.h>
#include <iostream>
#include <ds.hpp>
#include <string.h>

/* mpk为顶级域的sP */
int run_ibe_verify(struct SignMesg *sig, IBEPublicParameters *mpk, const char *id, size_t id_len)
{
    int rnt = 0;
    if(sig->front!=nullptr)
    {
        run_ibe_verify(sig->front, mpk, sig->front->ID, strlen(sig->front->ID));
        IBEPublicParameters *test_mpk = NULL;
        // test_mpk = sig->front->PP;
        // char *mes_id;
        // mes_id = ctx->get_src_id()->id;
        // size_t id_len = strlen(mes_id);
        // char *data = (char *)malloc(id_len + IBE_MPK_LEN);
        // memcpy(data, mes_mpk, IBE_MPK_LEN);
        // memcpy(data + IBE_MPK_LEN, mes_id, id_len);

        // if(!ibe_verify(data, id_len + IBE_MPK_LEN, sign->sign_data, strlen(sign->sign_data), &mpk, 239, ctx->get_src_id()->father_node->id, strlen(ctx->get_src_id()->father_node->id)))
        // {
        //     fprintf(stderr, "verify error\n");
        // } 
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