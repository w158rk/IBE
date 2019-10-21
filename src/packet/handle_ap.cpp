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
}

#include <iostream>
#include <packet.hpp>
#define DEBUG
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
    fprintf(stderr, "payload: %s\n", payload);
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
    fprintf(stderr, "payload1: %s\n", payload);
    #endif

    /*生成私钥sk*/
    if ( 0 == ibe_extract(&sk, &msk, payload+SM4_KEY_LEN, (size_t)id_len)) {
        ERROR(" cannot extract the private key");
        throw std::exception();
    }       

    fprintf(stderr, "sk id%s\n", sk);

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
    send_packet.payload = ptr;        //payload中存放私钥
    send_ctx.phase = SEND_APP_PACKET;
    send_ctx.payload.appPacket = &send_packet;
    #ifdef DEBUG
    int N = strlen(send_ctx.payload.appPacket->payload);
    fprintf(stderr,"len is: %d\n",N);
    #endif
     #ifdef DEBUG 
    fprintf(stderr, "payload2: %x\n", payload);
    for(int t=0;t<16;t++)
		printf("%02x ",payload[t]);
	printf("\n");
    #endif
    char *sm4_key= (char *)malloc(SM4_KEY_LEN);
	memcpy(sm4_key, payload, 16);
    #ifdef DEBUG
	fprintf(stderr, "sm4_key is:%s\n", sm4_key);
	for(int t=0;t<16;t++)
		printf("%02x ",sm4_key[t]);
	printf("\n");
    #endif

    send_ctx.key= sm4_key;

    #ifdef DEBUG
    fprintf(stderr, "payload3: %s\n", payload);
    fprintf(stderr, "send_ctx.sm4_key): %s\n", send_ctx.key);
    //fprintf(stderr, "sm4_key: %x\n", send_ctx.sm4_key);
    #endif

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

    FILE *fp;
    int filename_len = ctx->dest_id->length + 9;
    char *filename = (char *)malloc(filename_len);
    filename[0] = 's';
    filename[1] = 'k';
    filename[2] = '_';
    memcpy(filename + 3, ctx->dest_id->id, ctx->dest_id->length);
    filename[filename_len-6] = '.'; 
    filename[filename_len-5] = 'c'; 
    filename[filename_len-4] = 'o'; 
    filename[filename_len-3] = 'n'; 
    filename[filename_len-2] = 'f';
    filename[filename_len-1] = '\0';
    #ifdef DEBUG
    fprintf(stderr, "sk_filename is%s\n", filename);
    #endif
    /*if((fp=fopen(filename,"rb+"))==NULL)
    {
        printf("file cannot open \n");  
    }
    int i=0;
    char sk[100000],temp[10000];
    while(fgets(temp,1001,fp)){
		for(int j=0;temp[j]!='\0';i++,j++){
			sk[i]=temp[j];
		}
	}
	sk[i]='\0';
    fclose(fp);*/
    IBEPrivateKey sk;
    get_sk_fp(filename, &sk);
    fprintf(stderr, "The private key is:%s\n", sk);
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
    //fprintf(stderr,"Here\n");
    //fprintf(stderr, "out is%s\n", out);
    if(data_len!=out_len || memcmp(data, out, out_len)!=0)
    {
        fprintf(stderr, "sk is wrong\n");
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
    fprintf(stderr, "message is:%s\n",p->payload);
    fprintf(stderr,"the length is:%d", length);
    #endif
    char *message = (char *)malloc(length);
    strncpy(message, p->payload, length);
    message[length]='\0';
    #ifdef DEBUG
    fprintf(stderr, "message is:%s\n", message);
    #endif
    FILE *fp;
    if((fp=fopen("dec_message.txt","wb+"))==NULL)
    {
        printf("file_massge cannot open \n");
		goto end;
    }
    fwrite(message, sizeof(char), length+1, fp);
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
    //fprintf(stderr, "payload is %s\n", get_ctx()->payload.appPacket->payload);
    //fprintf(stderr, "type : %d\n",  *(int *)(get_ctx()->payload.appPacket->head));
    PacketCTX *ctx = get_ctx();
    //fprintf(stderr, "payload is %s\n", ctx->payload.appPacket->payload);
    //fprintf(stderr, "type : %d\n",  *(int *)(ctx->payload.appPacket->head));
    AppPacket *p = ctx->payload.appPacket;
    // std::cout  << p->payload << std::endl;
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
