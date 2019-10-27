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
//#define DEBUG
using namespace packet;

int handle_m(Packet *target)
{
    int rtn = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->payload.appPacket;
    char *head = p->head;
    int length = *(int *)(head + 4);
    
    /*@todo forbid the overflow, but it may cause some other problem */
    p->payload[length] = '\0';     

    printf("receive message : %s\n", p->payload);
    rtn = 1;

end:

    return rtn;
}


int handle_sk_request(Packet *target) 
{

    int rtn = 0;
    PacketCTX *ctx = target->get_ctx();

    AppPacket *p = ctx->payload.appPacket;
    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d] payload : %s\n", __FILE__, __LINE__, p->payload);
    #endif
    char *head = p->head;
    char *payload = p->payload;        //获取的payload为client的SM4_key加上id

    /* It may cause some problem for not using the network order */
    int payload_len = *(int *)(head + 4);
    char *client_id = payload + SM4_KEY_LEN;
    int client_id_len = payload_len - SM4_KEY_LEN;       //计算id的长度

#ifdef DEBUG 
    fprintf(stderr, "payload_len: %d\n", payload_len);
    fprintf(stderr, "id_len is: %d\n", client_id_len);
    fprintf(stderr, "id: %s\n", client_id);
#endif

    IBEMasterSecret msk = NULL;
    IBEPrivateKey sk = NULL;

    interface::IUser *user= target->get_user_ptr();
    char *msk_filename = user->get_msk_filename();
    char *mpk_filename = user->get_mpk_filename();

    if (get_msk_fp(msk_filename, &msk) == 0) {
        ERROR(" you don't have the access to msk file");
        throw std::exception();
    }       //从文件中读取s

    // there is a bug that sucks 
    // it seems that the function get_msk_fp would change the value of p->payload 
    // i don't know why, may be some magic things

    /*生成私钥sk*/
    if ( 0 == ibe_extract(&sk, &msk, client_id, (size_t)client_id_len)) {
        throw PacketException(" cannot extract the private key");
    }       

#ifdef DEBUG 
        fprintf(stderr, "the generation of the private key passed \n");
#endif    

    {   /* test the validation of the private key*/
        char data[] = "This is a test text";
        char c_buf[BUFFER_SIZE] = {'\0'};
        size_t data_len = strlen(data);
        size_t c_len;

        IBEPublicParameters mpk = NULL;
        get_mpk_fp(mpk_filename, &mpk);		//从文件中读出sP的值

        ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, client_id, client_id_len);
        size_t out_len = BUFFER_SIZE;   
        char out[BUFFER_SIZE] = {'\0'};
        ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
        if(data_len!=out_len || memcmp(data, out, out_len)!=0)
        {
            fprintf(stderr, "extract sk fail\n");
        }
#ifdef DEBUG 
        fprintf(stderr, "the test of the private key passed \n");
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
    *(int *)(send_packet->head) = PRIVATE_KEY_RESPONSE_TYPE;
    *(int *)(send_packet->head+4) = IBE_SK_LEN;   


    // store the private key in the payload 
    // TODO : Not sure if it is necessary to copy the key from sk to psk 
    // If the sk is allocated in the stack, it is 
    // Otherwise, the following three lines can be replaced by a single line
    send_packet->payload = sk;        
    
    /** set the variables in the context 
     * 1. set the phase as SEND_ADD_PACKET 
     * 2. set the payload 
     * 3. key for decryption
     */
    send_ctx->phase = SEND_APP_PACKET;
    send_ctx->payload.appPacket = send_packet;

    char *sm4_key= (char *)std::malloc(SM4_KEY_LEN);
	memcpy(sm4_key, payload, 16);       //payload的前16位为sm4key
    send_ctx->key = sm4_key;      //sm4key放在send_ctx的key中

    // send the packet
#ifdef DEBUG 
    std::cerr << "begin sending" << std::endl;
#endif
    if(0 == target->packet_send(send_ctx)) {
        ERROR("send the p error");
        goto end;
    }

    rtn = 1;
end:
    /* free all the local allocated variable */
    delete send_ctx;
    delete send_packet;
    return rtn;

}


int handle_sk_response(Packet *target) {
    int rtn = 0;
// GENERATE_SK_FILENAME(ctx->dest_id)        

// fprintf(stderr, "sk_filename is%s\n", filename);
// FILE *fp2;
// if((fp2=fopen(filename,"wb+"))==NULL)
// {
//     printf("file cannot open \n");  
// }
// fprintf(fp2,"%s",sm4_cipher + APP_HEAD_LEN);
// fclose(fp2);
// fprintf(stderr,"sk_file generate\n");

// FREE_SK_FILENAME;

//     PacketCTX *ctx = target->get_ctx();
//     ID *dest_id = ctx->dest_id;

//     GENERATE_SK_FILENAME(ctx->dest_id)
// #ifdef DEBUG
//     fprintf(stderr, "sk_filename is%s\n", filename);
// #endif
//     IBEPrivateKey sk;
//     get_sk_fp(filename, &sk);       //从文件中获取sk

//     fprintf(stderr, "The private key is:%s\n", sk);
//     FREE_SK_FILENAME;
//     /*对sk能否进行成功加解密进行验证*/
//     char data[BUFFER_SIZE] = "This is a test text";
//     IBEPublicParameters mpk;
//     get_mpk_fp(MPK_FILENAME, &mpk);
//     size_t data_len = strlen(data);
//     char c_buf[BUFFER_SIZE] = {'\0'};
//     size_t c_len;
//     ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, CLIENT_ID, CLIENT_ID_LEN);
//     //fprintf(stderr, "cipher is: %s\n", c_buf);
//     size_t out_len = BUFFER_SIZE;   
//     char out[BUFFER_SIZE] = {'\0'};
//     ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
//     //fprintf(stderr, "out is%s\n", out);
//     if(data_len!=out_len || memcmp(data, out, out_len)!=0)
//     {
//         fprintf(stderr, "sk is wrong\n");
//     }
//     else
//     {
//         fprintf(stderr,"sk is correct\n");
//     }
    
    
    rtn = 1;

end:
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
    AppPacket *p = ctx->payload.appPacket;
    char *head = p->head;
    int length = *(int *)(head+4);
#ifdef DEBUG
    fprintf(stderr,"the length is:%d", length);
#endif

    char *message = p->payload;

    interface::IUI *ui = target->get_ui_ptr();
    ui->print(message, length);

    // FILE *fp;
    // if((fp=fopen("dec_message.txt","wb+"))==NULL)
    // {
    //     printf("file_massge cannot open \n");
	// 	goto end;
    // }
    // fwrite(message, sizeof(char), length, fp);
    // fclose(fp);
#ifdef DEBUG
    fprintf(stderr, "receive message done\n");
#endif

    rnt=1;
end:
    return rnt;
}


void Packet::handle_ap() {

    int rtn = 0;

    if(get_ctx()->phase != RECV_APP_PACKET) {
        throw PacketException("call wrong function");
    }
    PacketCTX *ctx = get_ctx();
    AppPacket *p = ctx->payload.appPacket;
    char *head = p->head;

    /* analyze the head */
    int type = *(int *)head;

#ifdef DEBUG 
    fprintf(stderr, "[%s : %d]type : %d\n", __FILE__, __LINE__, type);
#endif

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
    
    get_ctx()->phase = RECV_DONE;
    rtn = 1;
}
