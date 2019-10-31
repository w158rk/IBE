
extern "C" {
#include <crypto.h>
#include <sys.h>
#include <utils.h>
#include <string.h>
#include <config.h>
}

#include<packet.hpp>


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
    SecPacket *p_sec_packet = ctx->get_payload_sec();

    int crypto_type = p_sec_packet->get_type();

    switch (crypto_type)
    {
    case NO_ENC_TYPE:
        /* code */
        break;
    case IBE_TYPE:
    {
        // get the cipher length and allocate space for decryption
        int c_len = p_sec_packet->get_length();
        char *m = (char *)malloc(BUFFER_SIZE);
        size_t m_len;

        // get the private key from file
        IBEPrivateKey sk = NULL;

        GENERATE_SK_FILENAME((ctx->get_dest_id()))
        get_sk_fp(filename, &sk);

        // decrypt
        if(0 == ibe_decrypt(p_sec_packet->get_payload_byte(), c_len, m, &m_len, &sk))
        {
            interface::IUI::error("ibe decryption failed");
            throw PacketException("ibe decryption failed");
        }
        std::free(sk);
        FREE_SK_FILENAME;

        // organize the message as a app packet 
        // so the initial sec packet should be released 
        // after the verification finished
        // so run a deep copy, no pointers transferred in 
        // this function 
        AppPacket *p_app_packet = new AppPacket;

        // the head is the first 8 bytes of the decrypted message
        p_app_packet->set_head(m);
        
        // copy the rest of the message into the payload of app packet
        int payload_len = p_app_packet->get_length();                 
        char *payload = (char *)std::malloc(payload_len);
        memcpy(payload, m+APP_HEAD_LEN, payload_len);
        p_app_packet->set_payload(payload);     


        // add the app packet to the payload of the sec packet 
        p_sec_packet->set_payload_app(p_app_packet);       //把该app_packet包放在ctx->payload.secPacket->payload.appPacket中

        break;
    }

    case SM4_TYPE:
    {
        sm4_context sm4ctx;

        // get the key from the packet object
        sm4_setkey_dec(&sm4ctx, (unsigned char*)get_user_ptr()->get_sm4_key());

        // allocate space for decryption
        int length = p_sec_packet->get_length();
        char *sm4_msg = (char *)std::malloc(BUFFER_SIZE);
        int out_len;
	    sm4_crypt_ecb(&sm4ctx, 
                        DEC_PARAMETER, 
                        length, 
                        (unsigned char*)(p_sec_packet->get_payload_byte()),
                        (unsigned char*)sm4_msg,
                        &out_len);
        
        // create a new app packet 
        AppPacket *p_app_packet = new AppPacket;
        char *payload = (char *)std::malloc(length-APP_HEAD_LEN);

        // copy the header and the payload into the app packet
        p_app_packet->set_head(sm4_msg);
        p_app_packet->set_payload(sm4_msg+APP_HEAD_LEN);

         try
        {
            std::free(p_sec_packet->get_payload_byte());
            std::free(sm4_msg);
        }
        catch(std::exception &e)
        {
            interface::IUI::error(e.what());
            throw PacketException(e.what());
        }

        // set the payload of the sec packet        
        p_sec_packet->set_payload_app(p_app_packet);

        break;
    }
        
    default:
        break;
    }

    ctx->set_phase(RECV_VERIFY);
}
