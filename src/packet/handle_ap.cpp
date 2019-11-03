/**
 * @file handle_ap.c 
 * @author Wang Ruikai 
 * @date August 8th, 2019 
 * @brief handle the p in the App Packet phase
 */

extern "C" {
    #include <crypto.h>
    #include <sys.h>
    #include <string.h>
    #include <config.h>
    #include<utils.h>
}

#include <iostream>
#include <packet.hpp>

using namespace packet;

int handle_m(Packet *target)
{
    int rtn = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    
    /*@todo forbid the overflow, but it may cause some other problem */
    interface::IUI::print(p->get_payload(), length);
    rtn = 1;

    return rtn;
}


int handle_sk_request(Packet *target) 
{

    int rtn = 0;
    PacketCTX *ctx = target->get_ctx();

    AppPacket *p = ctx->get_payload_app();
    char *payload = p->get_payload();        //获取的payload为client的SM4_key加上id
    int payload_len = p->get_length();

    /* It may cause some problem for not using the network order */
    char *client_id = payload + SM4_KEY_LEN;
    int client_id_len = payload_len - SM4_KEY_LEN;       //计算id的长度

    IBEMasterSecret msk = NULL;
    IBEPrivateKey sk = NULL;

    interface::IUser *user= target->get_user_ptr();
    char *msk_filename = user->get_msk_filename();
    char *mpk_filename = user->get_mpk_filename();

    if (get_msk_fp(msk_filename, &msk) == 0) {
        interface::IUI::error(" you don't have the access to msk file");
        throw PacketException(" you don't have the access to msk file");
    }       //从文件中读取s

    // there is a bug that sucks 
    // it seems that the function get_msk_fp would change the value of p->payload 
    // i don't know why, may be some magic things

    /*生成私钥sk*/
    long sk_len;
    if ( 0 == ibe_extract(&sk,
                            &sk_len, 
                            &msk, 
                            target->get_user_ptr()->get_msk_len(),
                            client_id, 
                            (size_t)client_id_len)) {
        interface::IUI::error(" cannot extract the private key");
        throw PacketException(" cannot extract the private key");
    }       

    {   /* test the validation of the private key*/
        // char data[] = "This is a test text";
        // char c_buf[BUFFER_SIZE] = {'\0'};
        // size_t data_len = strlen(data);
        // size_t c_len;

        // IBEPublicParameters mpk = NULL;
        // get_mpk_fp(mpk_filename, &mpk);		//从文件中读出sP的值

        // ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, 
        //             target->get_user_ptr()->get_mpk_len(), client_id, client_id_len);
        // size_t out_len = BUFFER_SIZE;   
        // char out[BUFFER_SIZE] = {'\0'};
        // ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
        // if(data_len!=out_len || memcmp(data, out, out_len)!=0)
        // {
        //     interface::IUI::error("extract sk fail");
        // }
#ifdef DEBUG 
        interface::IUI::debug("the test of the private key passed");
#endif
    }

    // TODO 
    // finish extracting the requested private key 
    // the next step is to send the key to the client 
    // the following code is not checked

    PacketCTX *send_ctx = new PacketCTX;
    AppPacket *send_packet = new AppPacket;

    // store the type of the app packet and the length of the 
    // private key at the header of the packet
    send_packet->set_type(PRIVATE_KEY_RESPONSE_TYPE);
    send_packet->set_length(sk_len);

    // store the private key in the payload 
    // TODO : Not sure if it is necessary to copy the key from sk to psk 
    // If the sk is allocated in the stack, it is 
    // Otherwise, the following three lines can be replaced by a single line
    send_packet->set_payload (sk);        
    
    /** set the variables in the context 
     * 1. set the phase as SEND_ADD_PACKET 
     * 2. set the payload 
     * 3. key for decryption
     */
    send_ctx->set_phase (SEND_APP_PACKET);
    send_ctx->set_payload_app (send_packet);

    char *sm4_key= (char *)std::malloc(SM4_KEY_LEN);
	memcpy(sm4_key, payload, 16);       //payload的前16位为sm4key
    target->get_user_ptr()->set_sm4_key(sm4_key);

    // send the packet
#ifdef DEBUG 
    interface::IUI::debug("begin sending");
#endif
    if(0 == target->packet_send(send_ctx)) {
        ERROR("send the p error");
        goto end;
    }

    rtn = 1;
end:
    return rtn;

}


int handle_sk_response(Packet *target) {
    
    int rtn = 0;
    PacketCTX *ctx = target->get_ctx();

    AppPacket *p_app_packet = ctx->get_payload_app();
    int len = p_app_packet->get_length();
    char *sk = (char *)std::malloc(len);
    memcpy(sk, p_app_packet->get_payload(), len);

    GENERATE_SK_FILENAME(ctx->get_dest_id())        

#ifdef DEBUG
    interface::IUI::debug("sk_filename is " + std::string(filename));
#endif

    FILE *fp2;
    if((fp2=fopen(filename,"wb+"))==NULL)
    {
        interface::IUI::error("file cannot open \n");  
    }
    fprintf(fp2,"%s", sk);
    fclose(fp2);
#ifdef DEBUG
    interface::IUI::debug(std::string(filename) + " generated");
#endif

    FREE_SK_FILENAME;
    
    rtn = 1;
    return rtn;

}


int handle_session_request(Packet *target) {
    
}


int handle_session_ack(Packet *target) {

}


int handle_session_final(Packet *target) {

}

int handle_message(Packet *target)
{
    int rnt = -1;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();

    char *message = p->get_payload();

    interface::IUI::print(message, length);

#ifdef DEBUG
    interface::IUI::error("receive message done");
#endif

    rnt=1;
    return rnt;
}


void Packet::handle_ap() {

    int rtn = 0;

    if(get_ctx()->get_phase() != RECV_APP_PACKET) {
    interface::IUI::error("call wrong function handle ap");
        throw PacketException("call wrong function");
    }
    PacketCTX *ctx = get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int type = p->get_type();

    switch (type)
    {
        case PLAIN_MESSAGE_TYPE:
            handle_m(this);
            break;
        
        case PRIVATE_KEY_REQUEST_TYPE:
            handle_sk_request(this);
            break;
        
        case PRIVATE_KEY_RESPONSE_TYPE:
            handle_sk_response(this);
            break;
        
        case SESSION_KEY_REQUEST_TYPE:
            handle_session_request(this);
            break;

        case SESSION_KEY_ACK_TYPE:
            handle_session_ack(this);
            break;

        case SESSION_KEY_FINAL_TYPE:
            handle_session_final(this);
            break;

        case IBE_MES_TYPE:
            handle_message(this);
            break;
        
        default:
            ERROR("the p type is invalid");
            throw std::exception();
            break;
    }
    
    ctx->set_phase (RECV_DONE);
    rtn = 1;
}
