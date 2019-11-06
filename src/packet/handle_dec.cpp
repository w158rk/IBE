
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
#include<sstream>
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
        FREE_SK_FILENAME
        std::cout<<"cipher is"<<p_sec_packet->get_payload_byte()<<std::endl;
        std::cout<<"cipher len is"<<c_len<<std::endl;
        std::cout<<"sk is"<<sk<<std::endl;
        ibe_decrypt(p_sec_packet->get_payload_byte(), c_len, m, &m_len, 
                            &sk, get_user_ptr()->get_sk_len());
        std::cout<<"m is"<<m<<std::endl;
//         size_t m_len;

//         // get the private key from file
//         IBEPrivateKey sk = NULL;

//         GENERATE_SK_FILENAME((ctx->get_dest_id()))
//         get_sk_fp(filename, &sk);
//         FREE_SK_FILENAME

//         // decrypt
//         std::cout<<"cipher is"<<p_sec_packet->get_payload_byte()<<std::endl;
//         std::cout<<"cipher len is"<<c_len<<std::endl;
//         std::cout<<"sk is"<<sk<<std::endl;
//         std::cout<<"sk len is"<<get_user_ptr()->get_sk_len()<<std::endl;
//         char data[BUFFER_SIZE];
//         memcpy(data, p_sec_packet->get_payload_byte(), c_len+10);
//         if(0 == ibe_decrypt(data, c_len, m, &m_len, 
//                                 &sk, get_user_ptr()->get_sk_len()))
//         {
// #ifdef DEBUG            
//             std::ostringstream s;
//             s << "ibe decryption failed, length of cipher:" << c_len;
//             interface::IUI::error(s.str());

//             FILE* fp = std::fopen("tmp-dec", "wb");
//             std::fwrite(p_sec_packet->get_payload_byte(), c_len, 1, fp);
//             std::fclose(fp);
// #else
//             interface::IUI::error("ibe decryption failed");
// #endif
//             throw PacketException("ibe decryption failed");
//         }
        std::free(sk);

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
        std::cout<<"payload is"<<payload<<std::endl;
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
