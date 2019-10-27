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


int handle_sk_request(Packet *target) {

    int rtn = 0;
    PacketCTX *ctx = target->get_ctx();

    AppPacket *p = ctx->payload.appPacket;
    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d] payload : %s\n", __FILE__, __LINE__, p->payload);
    #endif
    char *head = p->head;
    char *payload = p->payload;        //获取的payload为client的SM4_key加上id

    /* It may cause some problem for not using the network order */
    //int payload_len = *(int *)(head + 4);
    int payload_len = strlen(payload);
    #ifdef DEBUG 
    fprintf(stderr, "payload_len: %d\n", payload_len);
    #endif
    int id_len = strlen(payload+SM4_KEY_LEN);       //计算id的长度

    IBEMasterSecret msk = NULL;
    IBEPrivateKey sk = NULL;

    if (get_msk_fp(MSK_FILENAME, &msk) == 0) {
        ERROR(" you don't have the access to msk file");
        throw std::exception();
    }       //从文件中读取s

    // there is a but that sucks 
    // it seems that the function get_msk_fp would change the value of p->payload 
    // i don't know why, may be some magic things

    #ifdef DEBUG 
    fprintf(stderr, "id_len is: %d\n", id_len);
    fprintf(stderr, "[%s : %d] extract finished\n", __FILE__, __LINE__);
    fprintf(stderr, "&msk : %ld \n", msk);
    fprintf(stderr, "id: %s", payload + SM4_KEY_LEN);
    fprintf(stderr, "payload: %s\n", payload);
    #endif

    /*生成私钥sk*/
    if ( 0 == ibe_extract(&sk, &msk, payload+SM4_KEY_LEN, (size_t)id_len)) {
        ERROR(" cannot extract the private key");
        throw std::exception();
    }       

    fprintf(stderr, "sk id%s\n", sk);

    /*测试该sk能否成功加解密*/
    char data[BUFFER_SIZE] = "This is a test text";
   IBEPublicParameters mpk = NULL;
	get_mpk_fp(MPK_FILENAME, &mpk);		//从文件中读出sP的值
    size_t data_len = strlen(data);
    char c_buf[BUFFER_SIZE] = {'\0'};
    size_t c_len;
    ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, CLIENT_ID, CLIENT_ID_LEN);
    size_t out_len = BUFFER_SIZE;   
    char out[BUFFER_SIZE] = {'\0'};
    ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
   if(data_len!=out_len || memcmp(data, out, out_len)!=0)
   {
       fprintf(stderr, "extract sk fail %s\n");
   }

    // TODO 
    // finish extracting the requested private key 
    // the next step is to send the key to the client 
    // the following code is not checked

    PacketCTX send_ctx;
    AppPacket send_packet;

    *(int *)(send_packet.head) = PRIVATE_KEY_RESPONSE_TYPE;
    *(int *)(send_packet.head+4) = IBE_SK_LEN;      //头部存放了标示和私钥长度
    char *ptr = (char *)malloc(IBE_SK_LEN);
    memcpy(ptr, sk, IBE_SK_LEN);
    send_packet.payload = ptr;        //send_packet的payload中存放私钥
    send_ctx.phase = SEND_APP_PACKET;
    send_ctx.payload.appPacket = &send_packet;
    #ifdef DEBUG
    int N = strlen(send_ctx.payload.appPacket->payload);
    fprintf(stderr,"payload len is: %d\n",N);
    #endif
    char *sm4_key= (char *)malloc(SM4_KEY_LEN);
	memcpy(sm4_key, payload, 16);       //payload的前16位为sm4key
    #ifdef DEBUG
	fprintf(stderr, "sm4_key is:%s\n", sm4_key);
	for(int t=0;t<16;t++)
		printf("%02x ",sm4_key[t]);
	printf("\n");
    #endif

    send_ctx.key= sm4_key;      //sm4key放在send_ctx的key中

    if(0 == target->packet_send(&send_ctx)) {
        ERROR("send the p error");
        goto end;
    }

    rtn = 1;
end:
    free(sk);
    free(msk);
    return rtn;

}


int handle_sk_response(Packet *target) {
    int rtn = 0;

    PacketCTX *ctx = target->get_ctx();
    ID *dest_id = ctx->dest_id;
    GENERATE_SK_FILENAME(ctx->dest_id)
    #ifdef DEBUG
    fprintf(stderr, "sk_filename is%s\n", filename);
    #endif
    IBEPrivateKey sk;
    get_sk_fp(filename, &sk);       //从文件中获取sk
    fprintf(stderr, "The private key is:%s\n", sk);
    FREE_SK_FILENAME;
    /*对sk能否进行成功加解密进行验证*/
    char data[BUFFER_SIZE] = "This is a test text";
    IBEPublicParameters mpk;
    get_mpk_fp(MPK_FILENAME, &mpk);
    size_t data_len = strlen(data);
    char c_buf[BUFFER_SIZE] = {'\0'};
    size_t c_len;
    ibe_encrypt(data, data_len, c_buf, &c_len, &mpk, CLIENT_ID, CLIENT_ID_LEN);
    //fprintf(stderr, "cipher is: %s\n", c_buf);
    size_t out_len = BUFFER_SIZE;   
    char out[BUFFER_SIZE] = {'\0'};
    ibe_decrypt(c_buf, c_len, out, &out_len, &sk);
    //fprintf(stderr, "out is%s\n", out);
    if(data_len!=out_len || memcmp(data, out, out_len)!=0)
    {
        fprintf(stderr, "sk is wrong\n");
    }
    else
    {
        fprintf(stderr,"sk is correct\n");
    }
    
    
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
    PacketCTX *ctx = target->get_ctx();
    int rnt = -1;
    AppPacket *p = ctx->payload.appPacket;
    char *head = p->head;
    int length = *(int *)(head+4);
    #ifdef DEBUG
    fprintf(stderr,"the length is:%d", length);
    #endif
    char *message = (char *)malloc(length);
    strncpy(message, p->payload, length);       //message中存放解密后的信息
    message[length]='\0';
    #ifdef DEBUG
    fprintf(stderr, "message is:%s\n", message);
    #endif
    /*解密后的信息存放在dec_message.txt中*/
    FILE *fp;
    if((fp=fopen("dec_message.txt","wb+"))==NULL)
    {
        printf("file_massge cannot open \n");
		goto end;
    }
    fwrite(message, sizeof(char), length, fp);
    fclose(fp);
    fprintf(stderr, "receive message done\n");
    rnt=1;
end:
    return rnt;
}


void Packet::handle_ap() {

    int rtn = 0;

    if(get_ctx()->phase != RECV_APP_PACKET) {
        ERROR("call wrong function");
        throw std::exception();
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