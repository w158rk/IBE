
extern "C" {
#include <crypto.h>
#include <sys.h>
#include <utils.h>
#include <string.h>
#include <config.h>
}

#include<packet.hpp>

#define DEBUG
#ifdef DEBUG 
#include<iostream>
#endif

/**
 * At the beginning of this function, the ctx contains a sec packet 
 * whose payload is the encrypted message 
 * 
 * The function will get the encryption type from the header and 
 * find the keys somewhere, then decrypt the message and organize 
 * it as a app packet, which will be stored in the payload of 
 * the sec packet
 */
using namespace packet;
void Packet::handle_dec() {

    PacketCTX *ctx = get_ctx();

    /* packets */
    SecPacket *p_sec_packet = ctx->payload.secPacket;

    int crypto_type = *(int *)(p_sec_packet->head);

    switch (crypto_type)
    {
    case NO_ENC_TYPE:
        /* code */
        break;
    case IBE_TYPE:
    {
        // get the cipher length and allocate space for decryption
        int c_len = *(int *)(p_sec_packet->head+4);
        char *m = (char *)malloc(BUFFER_SIZE);
        size_t m_len;

#ifdef DEBUG 
        //std::cerr << "length before decryption: " << c_len << std::endl;
#endif

        // get the private key from file
        IBEPrivateKey sk = NULL;
        GENERATE_SK_FILENAME(ctx->dest_id)
        get_sk_fp(filename, &sk);

        // decrypt
        if(0 == ibe_decrypt(p_sec_packet->payload.data, c_len, m, &m_len, &sk))
        {
            throw PacketException("ibe decryption failed");
        }
        fprintf(stderr, "sk is%s\n", sk);
        std::free(sk);
        FREE_SK_FILENAME;

#ifdef DEBUG 
        fprintf(stderr, "message length : %d\n", m_len); 
        fprintf(stderr, "message : %s\n", m);
#endif

        // organize the message as a app packet 
        AppPacket *app_packet = new AppPacket;

        // the head is the first 8 bytes of the decrypted message
        memcpy(app_packet->head, m, APP_HEAD_LEN);       
        
        // copy the rest of the message into the payload of app packet
        int payload_len = *(int *)(m+4);                 
        char *payload = (char *)std::malloc(payload_len);
        memcpy(payload, m+APP_HEAD_LEN, payload_len);
        app_packet->payload = payload;     

#ifdef DEBUG 
        fprintf(stderr, "payload length : %d\n", payload_len);
        fprintf(stderr, "payload : %s\n", payload);
#endif

        // add the app packet to the payload of the sec packet 
        p_sec_packet->payload.appPacket = app_packet;       //把该app_packet包放在ctx->payload.secPacket->payload.appPacket中

        break;
    }

    case SM4_TYPE:
    {
        sm4_context sm4ctx;

        // get the key from the packet object
        sm4_setkey_dec(&sm4ctx, (unsigned char*)get_user_ptr()->get_sm4_key());

        // allocate space for decryption
        int length = *(int *)(p_sec_packet->head+4);
        unsigned char *sm4_msg = (unsigned char *)std::malloc(BUFFER_SIZE);
	    sm4_crypt_ecb(&sm4ctx, 
                        0, 
                        length, 
                        (unsigned char*)(p_sec_packet->payload.data),
                        sm4_msg);
#ifdef DEBUG
        fprintf(stderr, "id为：%s\n",ctx->dest_id->id);
#endif
        
        // create a new app packet 
        AppPacket *p_app_packet = new AppPacket;
        p_app_packet->payload = (char *)std::malloc(length-APP_HEAD_LEN);

        // copy the header and the payload into the app packet
        memcpy(p_app_packet->head, sm4_msg, APP_HEAD_LEN);        
        memcpy(p_app_packet->payload, sm4_msg+APP_HEAD_LEN, length-APP_HEAD_LEN);

        // set the payload of the sec packet        
         try
        {
            std::free(p_sec_packet->payload.data);
        }
        catch(std::exception &e)
        {
            std::cerr << e.what() << std::endl;
        }
       p_sec_packet->payload.appPacket = p_app_packet;

        // free the temporaries
        try
        {
            std::free(sm4_msg);
        }
        catch(std::exception &e)
        {
            std::cerr << e.what() << std::endl;
        }

        break;
    }
        
    default:
        break;
    }

    ctx->phase = RECV_VERIFY;
end:
    //#ifdef DEBUG 
    fprintf(stderr, "return test\n");
    //#endif
}