/**
 * @file send_enc.c
 * @author Wang Ruikai 
 * @date August 9th, 2019 
 * @brief encrypt the app_packet
 */

extern "C" {
    #include <crypto.h>
    #include <string.h>
    #include <sys.h>
    #include <time.h>
}

#include <ui.hpp>
#include "packet_lcl.hpp"
#include<config.h>
#define DEBUG
#ifdef DEBUG 
#include<iostream>
#include<sstream>
#endif

using namespace packet;

#define Error(err) throw PacketException(err)
#define Debug(info) ui::UInterface::debug(info)
// at this phase, there is a sec packet in the 
// ctx object, so the app packet is in the payload 
// of that sec packet
void Packet::send_enc()
{
    user::User *user_ptr = get_user_ptr();
    PacketCTX *ctx = get_ctx();

    if(ctx->get_phase() != SEND_ENC) {
        interface::IUI::error("call wrong function");
        throw PacketException("call wrong function");
    }

    SecPacket *p_sec_packet = ctx->get_payload_sec();
    int sec_type = p_sec_packet->get_type();

    AppPacket *p_app_packet = p_sec_packet->get_payload_app();
    int app_length = p_app_packet->get_length();

    switch (sec_type)
    {
        case IBE_DOMAIN_TYPE:
        case IBE_TYPE:
        {
            // encrypt the message with the IBE encryption
            char *cipher = (char *)std::malloc(BUFFER_SIZE);
            size_t cipher_len = BUFFER_SIZE;

            int len = (size_t)app_length+APP_HEAD_LEN;
            char data[BUFFER_SIZE];
            memcpy(data, p_app_packet->to_bytes(), len);
            // std::cout<<data<<std::endl;
            // encrypt
            IBEPublicParameters mpk = NULL;
            GENERATE_MPK_FILENAME(ctx->get_dest_id()->id,strlen(ctx->get_dest_id()->id))
            get_mpk_fp(mpk_filename, &mpk);
            FREE_MPK_FILENAME;

// #ifdef DEBUG 
// {
//             std::ostringstream s;
//             s << "Get mpk file: " << user_get_mpk_filename(user_ptr) << std::endl;
//             Debug(s.str()); 
// }
// #endif
//             if(!get_mpk_fp(user_get_mpk_filename(user_ptr), &mpk))
//             {
//                 Error("cannot get mpk from file");
//             }
#ifdef DEBUG 
{
            std::ostringstream s;
            s << "size of data: " << len;
            Debug(s.str());
}
#endif
            if (!ibe_encrypt(data, 
                        len, 
                        cipher, 
                        &cipher_len, 
                        &mpk,
                        user_get_mpk_len(user_ptr),
                        ctx->get_dest_id()->id, 
                        ctx->get_dest_id()->length))
            {
                Error("encrypt failed");
            }
            
#ifdef DEBUG
            std::ostringstream s;
            s << "ibe encryption finished, length of cipher:" << cipher_len << std::endl;
            s << ". ID used in the process: " << ctx->get_dest_id()->id << std::endl;
            interface::IUI::debug(s.str());
#endif
            // copy the cipher into the sec packet
            char *tmp = (char *)std::malloc(cipher_len);
            memcpy(tmp, cipher, cipher_len);       //将加密后的数据放到sec_packet的payload.data中

// #ifdef DEBUG
// {
//             char *m = (char *)malloc(BUFFER_SIZE);
//             size_t m_len =BUFFER_SIZE;
//             IBEPrivateKey sk = NULL;
//             get_sk_fp("sk_Server.conf", &sk);
//             std::cout<<"cipher is "<<cipher<<std::endl;
//             std::cout<<"cipher len is "<<cipher_len<<std::endl;
//             std::cout<<"sk is "<<sk<<std::endl;
//             ibe_decrypt(cipher, cipher_len, m, &m_len, 
//                                 &sk, 380);
//             std::cout<<"m is "<<m<<std::endl;
// }
// #endif
            p_sec_packet->set_payload_byte(tmp);

#ifdef DEBUG
            FILE* fp = std::fopen("tmp-enc", "wb");
            std::fwrite(p_sec_packet->get_payload_byte(), cipher_len, 1, fp);
            std::fclose(fp);
#endif
            // length without header 
            p_sec_packet->set_length((int)cipher_len);

            // free the temporaries
            std::free(cipher);

            /**
             * be careful that the tmp is not freed in this function 
             */

            break;
        }
    
        case SM4_TYPE:
        {   
            
            // allocate space for plain data and cipher
            char *data = p_app_packet->to_bytes();
            char *cipher = (char *)std::malloc(BUFFER_SIZE);

#ifdef DEBUG
            char *output = (char *)malloc(BUFFER_SIZE);
#endif

            int len = app_length + APP_HEAD_LEN;
            int c_len;
            double start,end,cost;
            start=clock();
            sm4_context *sm4ctx = new sm4_context;

            // get sm4 key from users directly
            sm4_setkey_enc(sm4ctx,(unsigned char*)(user_get_sm4_key(user_ptr)));
            sm4_crypt_ecb(sm4ctx, ENC_PARAMETER, app_length + APP_HEAD_LEN, 
                            (unsigned char*)data, (unsigned char*)cipher, &c_len);
            end=clock();
            cost=(end-start)/CLOCKS_PER_SEC*1000;
            printf("sm4enc time is: %f ms\n",cost);
                 
#ifdef DEBUG
{
            /*对生成的cipher进行验证是否正确*/
            sm4_setkey_dec(sm4ctx, (unsigned char*)user_get_sm4_key(user_ptr));
            unsigned char *tmp = (unsigned char *)std::malloc(c_len);
            memcpy(tmp, cipher, c_len);
            int out_len;
            sm4_crypt_ecb(sm4ctx,DEC_PARAMETER,c_len,(unsigned char*)tmp, (unsigned char*)output, &out_len);
}
#endif

            /**
             * TODO : calculate the cipher length from somewhere
             * here the segmentation fault is likely to happen
             */
            char *tmp = (char *)std::malloc(c_len);
            memcpy(tmp, cipher, c_len);       //加密后的信息放在sec_packet下的payload.sk_data中
            p_sec_packet->set_payload_byte(tmp);
            p_sec_packet->set_length(c_len);
            
            break;
        }
        
    
    default:    /* not encrypted */
    {
        char *data = p_app_packet->to_bytes();
        int len = app_length + APP_HEAD_LEN;
        p_sec_packet->set_payload_byte(data);
        p_sec_packet->set_length(len);
    }    
        
    }

    delete p_app_packet;
    ctx->set_phase(SEND_SEC_PACKET);
}
