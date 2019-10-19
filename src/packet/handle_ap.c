/**
 * @file handle_ap.c 
 * @author Wang Ruikai 
 * @date August 8th, 2019 
 * @brief handle the packet in the App Packet phase
 */

#include <packet.h>
#include <crypto.h>
#include <sys.h>
#include <string.h>
#include <ctx.h>
//#define DEBUG

int handle_m(PacketCTX *ctx)
{
    int rtn = 0;

    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;
    int length = *(int *)(head + 4);
    
    /*@todo forbid the overflow, but it may cause some other problem */
    packet->payload[length] = '\0';     

    printf("receive message : %s\n", packet->payload);
    rtn = 1;

end:

    return rtn;
}


int handle_sk_request(PacketCTX *ctx) {

    int rtn = 0;

    AppPacket *packet = ctx->payload.appPacket;
    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d] payload : %s\n", __FILE__, __LINE__, packet->payload);
    #endif
    char *head = packet->head;
    unsigned char *payload = packet->payload;        //获取的payload为client的SM4_key加上id

    /* It may cause some problem for not using the network order */
    //int payload_len = *(int *)(head + 4);
    int payload_len = strlen(payload);
    #ifdef DEBUG 
    fprintf(stderr, "payload: %x-\n", payload);
    fprintf(stderr, "payload_len: %d\n", payload_len);
    #endif
    int id_len = strlen(payload+SM4_KEY_LEN);       //计算id的长度

    IBEMasterSecret msk = NULL;
    IBEPrivateKey sk = NULL;

    if (get_msk_fp(MSK_FILENAME, &msk) == 0) {
        ERROR(" you don't have the access to msk file");
        goto end;
    }       //从文件中读取s

    // there is a but that sucks 
    // it seems that the function get_msk_fp would change the value of packet->payload 
    // i don't know why, may be some magic things

    #ifdef DEBUG 
    fprintf(stderr, "id_len is: %d\n", id_len);
    fprintf("[%s : %d] extract finished\n", __FILE__, __LINE__);
    fprintf(stderr, "&msk : %ld \n", msk);
    fprintf(stderr, "id: %s", payload + SM4_KEY_LEN);
    fprintf(stderr, "payload1: %x\n", payload);
    #endif

    /*生成私钥sk*/
    if ( 0 == ibe_extract(&sk, &msk, payload+SM4_KEY_LEN, (size_t)id_len)) {
        ERROR(" cannot extract the private key");
        goto end;
    }       
    fprintf(stderr, "[%s : %d] extract finished\n", __FILE__, __LINE__);
    fprintf(stderr,"sk is:%s ", sk);
    /*int sk_len = strlen(sk);
    fprintf(stderr, "sk length is :%s\n", sk);*/

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
       fprintf(stderr, "extract sk fail %s\n");
   }

    /*FILE *fp;
    if((fp=fopen("skClient.conf","wb+"))==NULL)
    {
        printf("file cannot open \n");  
    }
    fprintf(fp, "%s", sk);
    fclose(fp);*/

    // TODO 
    // finish extracting the requested private key 
    // the next step is to send the key to the client 
    // the following code is not checked

    PacketCTX send_ctx;
    AppPacket send_packet;

    *(int *)(send_packet.head) = PRIVATE_KEY_RESPONSE_TYPE;
    *(int *)(send_packet.head+4) = IBE_SK_LEN;      //头部存放了标示和私钥长度
    char *p = (char *)malloc(IBE_SK_LEN);
    memcpy(p, sk, IBE_SK_LEN);
    send_packet.payload = p;        //payload中存放私钥
    send_ctx.phase = SEND_APP_PACKET;
    send_ctx.payload.appPacket = &send_packet;
    #ifdef DEBUG
    int N = strlen(send_ctx.payload.appPacket->payload);
    fprintf(stderr,"len is: %d\n",N);
    #endif
    send_ctx.write_file = ctx -> write_file;
    send_ctx.read_file = ctx -> read_file;
     #ifdef DEBUG 
    fprintf(stderr, "payload2: %x\n", payload);
    for(int t=0;t<16;t++)
		printf("%02x ",payload[t]);
	printf("\n");
    #endif
    char *sm4_key= (char *)malloc(SM4_KEY_LEN);
	strncpy(sm4_key, payload, 16);
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

    if(0 == packet_send(&send_ctx)) {
        ERROR("send the packet error");
        goto end;
    }

    rtn = 1;
end:
    free(sk);
    free(msk);
    return rtn;

}


int handle_sk_response(PacketCTX *ctx) {
    int rtn = 0;

    FILE *fp;
    int filename_len = ctx->dest_id_len + 9;
    char *filename = (char *)malloc(filename_len);
    filename[0] = 's';
    filename[1] = 'k';
    filename[2] = '_';
    memcpy(filename + 3, ctx->dest_id, ctx->dest_id_len);
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


int handle_session_request(PacketCTX *ctx) {
    
}


int handle_session_ack(PacketCTX *ctx) {

}


int handle_session_final(PacketCTX *ctx) {

}

int handle_message(PacketCTX *ctx)
{
    int rnt = -1;
    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;
    int length = *(int *)(head+4);
    #ifdef DEBUG
    fprintf(stderr, "message is:%s\n",packet->payload);
    fprintf(stderr,"the length is:%d", length);
    #endif
    char *message = (char *)malloc(length);
    strncpy(message, packet->payload, length);
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


int handle_ap(PacketCTX *ctx) {

    int rtn = 0;

    if(ctx->phase != RECV_APP_PACKET) {
        ERROR("call wrong function");
        goto end;
    }

    AppPacket *packet = ctx->payload.appPacket;
    char *head = packet->head;

    /* analyze the head */
    int type = *(int *)head;

    #ifdef DEBUG 
    fprintf(stderr, "[%s : %d]type : %d\n", __FILE__, __LINE__, type);
    #endif

    switch (type)
    {
        case PLAIN_MESSAGE_TYPE:
            handle_m(ctx);
            break;
        
        case PRIVATE_KEY_REQUEST_TYPE:
            handle_sk_request(ctx);
            break;
        
        case PRIVATE_KEY_RESPONSE_TYPE:
            handle_sk_response(ctx);
            break;
        
        case SESSION_KEY_REQUEST_TYPE:
            handle_session_request(ctx);
            break;

        case SESSION_KEY_ACK_TYPE:
            handle_session_ack(ctx);
            break;

        case SESSION_KEY_FINAL_TYPE:
            handle_session_final(ctx);
            break;

        case IBE_MES_TYPE:
            handle_message(ctx);
            break;
        
        default:
            ERROR("the packet type is invalid");
            goto end;
            break;
    }
    ctx->phase = RECV_DONE;
    rtn = 1;
end:
    return rtn;
}
