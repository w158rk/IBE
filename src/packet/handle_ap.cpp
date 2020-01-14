/**
 * @file handle_ap.c 
 * @author Wang Ruikai 
 * @date August 8th, 2019 
 * @brief handle the p in the App Packet phase
 */

#include <crypto.h>
#include <sys.h>
#include <string.h>
#include <config.h>
#include <utils.h>
#include <ss.h>

#include <iostream>
#include <sstream>
#include "packet_lcl.hpp"
#include <ui.hpp>
#include <byte.hpp>

using namespace packet;

# define Error(err) throw PacketException(err)
# define Debug(info) ui::UInterface::debug(info)
# define Print(info) ui::UInterface::print(info)
# define Print2(a,b) ui::UInterface::print(a,b)

int handle_m(Packet *target)
{
    int rtn = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    
    /*@todo forbid the overflow, but it may cause some other problem */
    Print2(p->get_payload(), length);
    rtn = 1;

    return rtn;
}


int handle_sk_request(Packet *target) 
{

    int rtn = 0;
    PacketCTX *ctx = target->get_ctx();

    AppPacket *p = ctx->get_payload_app();
    char *payload = p->get_payload();        //payload:SM4_key||id
    int payload_len = p->get_length();

    /* It may cause some problem for not using the network order */
    char *client_id = payload + SM4_KEY_LEN;
    int client_id_len = payload_len - SM4_KEY_LEN;

    IBEMasterSecret msk = NULL;
    IBEPrivateKey sk = NULL;

    /* read msk */
    user::User *user= target->get_user_ptr();
    char *msk_filename = user_get_msk_filename(user);
    if (get_msk_fp(msk_filename, &msk) == 0) {
        interface::IUI::error(" you don't have the access to msk file");
        throw PacketException(" you don't have the access to msk file");
    }

    // there is a bug that sucks 
    // it seems that the function get_msk_fp would change the value of p->payload 
    // i don't know why, may be some magic things

    /*generate sk*/
    long sk_len;
    if ( 0 == ibe_extract(&sk,
                            &sk_len, 
                            &msk, 
                            user_get_msk_len(target->get_user_ptr()),
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

    SignMesg *server_sig = new SignMesg();

    /* get global-sP */
    IBEPublicParameters ss_mpk = NULL;
    get_mpk_fp(GLOBAL_MPK_FILENAME, &ss_mpk);

    /* get sig */
    GENERATE_SIGN_LEN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id)) 

    FILE *fp1; 
    if((fp1=fopen(filename_len_sign,"rb"))==NULL)
    {
        interface::IUI::error("sign_len file cannot open \n");  
    }
    int sg_len;
    std::fread(&sg_len, sizeof(sg_len), 1, fp1);
    fclose(fp1);

    FREE_SIGN_LEN_FILENAME;

    GENERATE_SIGN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id)) 

    FILE *fp;
    if((fp=fopen(filename_sign,"rb+"))==NULL)
    {
        interface::IUI::error("sign file cannot open \n");  
    }
    char *sign = (char*)malloc(sg_len);
    if(!fread(sign, 1, sg_len, fp))
    {
        printf("error in read file \n");
        throw std::exception();
    }
    fclose(fp);

    FREE_SIGN_FILENAME;

    server_sig = sign_from_bytes(sign, sg_len, 0);

    /* generate client sig */

    /* get own mpk */
    IBEPublicParameters mpk = NULL;
    ID *user_id = user_get_id(user);
    GENERATE_MPK_FILENAME(user_id->id, strlen(user_id->id));
    get_mpk_fp(mpk_filename, &mpk);
    FREE_MPK_FILENAME;
    char *data = (char *)malloc(client_id_len+IBE_MPK_LEN);
    memcpy(data,client_id, client_id_len);
    memcpy(data+client_id_len,mpk,IBE_MPK_LEN);
     
    // IBEPrivateKey server_sk = NULL;
    // GENERATE_SK_FILENAME((ctx->get_dest_id()))
    // get_sk_fp(filename, &server_sk);
    // FREE_SK_FILENAME
    IBEPrivateKey server_sk = NULL;
{
    char *filename = user_get_sk_filename(user);
    get_sk_fp(filename, &server_sk);
    free(filename);

}
    char *client_sign = (char *)std::malloc(BUFFER_SIZE);
    size_t sign_len = BUFFER_SIZE;

    if(!(ibe_sign(data, client_id_len+IBE_MPK_LEN, client_sign, &sign_len, &server_sk, 380)))
    {
        fprintf(stderr, "sign error\n");
        return -1;
    }

    SignMesg send_sig;
    send_sig.ID = client_id;
    send_sig.PP = mpk;
    send_sig.sign_data = client_sign;
    *(int *)(send_sig.id_len) = client_id_len;
    *(int *)(send_sig.sign_len) = sign_len;
    send_sig.front = server_sig;

    char *sig = (char *)malloc(BUFFER_LEN);
    int sig_len = sign_to_bytes(&send_sig, sig);
    // SignMesg *test = sign_from_bytes(sig, sig_len, 0);

    // if(!ibe_verify(data, client_id_len+IBE_MPK_LEN, test->sign_data, *(int *)test->sign_len, &test->PP, 239, "Server", 6))
    // {
    //     fprintf(stderr, "verify error\n");
    // }

     // TODO 
    // finish extracting the requested private key 
    // the next step is to send the key to the client 
    // the following code is not checked

    PacketCTX *send_ctx = new PacketCTX;
    AppPacket *send_packet = new AppPacket;

    // store the type of the app packet and the length of the 
    // private key at the header of the packet
    send_packet->set_type(PRIVATE_KEY_RESPONSE_TYPE);
    send_packet->set_length(sk_len + sig_len);

    char *send_payload = (char *)malloc(sk_len + sig_len);
    memcpy(send_payload, sk, sk_len);
    memcpy(send_payload+sk_len, sig, sig_len);

    // store the private key in the payload 
    // TODO : Not sure if it is necessary to copy the key from sk to psk 
    // If the sk is allocated in the stack, it is 
    // Otherwise, the following three lines can be replaced by a single line
    send_packet->set_payload (send_payload);

    /** set the variables in the context 
     * 1. set the phase as SEND_ADD_PACKET 
     * 2. set the payload 
     * 3. key for decryption
     */
    send_ctx->set_phase (SEND_APP_PACKET);
    send_ctx->set_payload_app (send_packet);

    char *sm4_key= (char *)std::malloc(SM4_KEY_LEN);
	memcpy(sm4_key, payload, SM4_KEY_LEN);       //payload的前16位为sm4key
    user_set_sm4_key(target->get_user_ptr(), sm4_key);

    // send the packet
#ifdef DEBUG 
    interface::IUI::debug("begin sending");
#endif
    if(0 == target->packet_send(send_ctx)) {
        Error("send the p error");
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
    char *sk = (char *)std::malloc(IBE_SK_LEN);
    memcpy(sk, p_app_packet->get_payload(), IBE_SK_LEN);
    int sign_len = len-IBE_SK_LEN;
    char *sign = (char *)malloc(sign_len);
    memcpy(sign, p_app_packet->get_payload()+IBE_SK_LEN, sign_len);
    // SignMesg *test = sign_from_bytes(sign, len-IBE_SK_LEN, 0);

    /* save sk file */
    GENERATE_DOMAIN_SK_FILENAME(ctx->get_dest_id())        
#ifdef DEBUG
    interface::IUI::debug("sk_filename is " + std::string(domain_filename));
#endif
    IBEPrivateKey *sk_ibe = &sk;
    put_sk_fp(domain_filename, sk_ibe, IBE_SK_LEN);

#ifdef DEBUG
    interface::IUI::debug(std::string(domain_filename) + " generated");
#endif
    FREE_DOMAIN_SK_FILENAME;

    int sk_len = IBE_SK_LEN;
    GENERATE_SKLEN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id)) 
    FILE *fp = std::fopen(filename, "wb");
    std::fwrite(&sk_len, sizeof(sk_len), 1, fp);
    std::fclose(fp);
    FREE_SK_LEN_FILENAME;

    /* save sign file */
    GENERATE_SIGN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id)) 
    FILE *fp2;
    if((fp2=fopen(filename_sign,"wb+"))==NULL)
    {
        interface::IUI::error("file cannot open \n");  
    }
    std::fwrite(sign, 1,  sign_len, fp2);
    fclose(fp2);
    FREE_SIGN_FILENAME;

    /* save sign len file */
    GENERATE_SIGN_LEN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id)) 
    FILE *fp3;
    if((fp3=fopen(filename_len_sign,"wb+"))==NULL)
    {
        interface::IUI::error("file cannot open \n");  
    }
    std::fwrite(&sign_len, sizeof(sign_len), 1, fp3);
    fclose(fp3);
    FREE_SIGN_LEN_FILENAME;

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
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();

    char *message = p->get_payload();

    interface::IUI::print(message, length);

#ifdef DEBUG
    interface::IUI::print("receive message done");
#endif

    rnt=1;
    return rnt;
}

int handle_mpk_request(Packet *target)
{
    int rtn = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    char *payload = p->get_payload();

    PacketCTX *send_ctx = new PacketCTX;
    AppPacket *send_packet = new AppPacket;

    IBEPublicParameters global_mpk = NULL;
    IBEPublicParameters mpk = NULL;

    user::User *user= target->get_user_ptr();
    char *mpk_filename = user_get_mpk_filename(user);
    if (get_mpk_fp(mpk_filename, &mpk) == 0) {
        interface::IUI::error(" you don't have the access to mpk file");
        throw PacketException(" you don't have the access to mpk file");
    }

    if (get_mpk_fp(GLOBAL_MPK_FILENAME, &global_mpk) == 0) {
        interface::IUI::error(" you don't have the access to global_mpk file");
        throw PacketException(" you don't have the access to global_mpk file");
    }

    char *send_payload = (char*)malloc(IBE_MPK_LEN+IBE_MPK_LEN);
    memcpy(send_payload,global_mpk,IBE_MPK_LEN);
    memcpy(send_payload+IBE_MPK_LEN,mpk,IBE_MPK_LEN);

    send_packet->set_type(MPK_RESPONSE_TYPE);
    send_packet->set_length(IBE_MPK_LEN+IBE_MPK_LEN);
    send_packet->set_payload(send_payload);

    send_ctx->set_phase (SEND_APP_PACKET);
    send_ctx->set_payload_app (send_packet);

    if(0 == target->packet_send(send_ctx)) {
        Error("send the p error");
        goto end;
    }

    rtn = 1;

end:
    return rtn;
}

int handle_mpk_response(Packet *target)
{
    int rtn = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    char *payload = p->get_payload();
    char *global_mpk = (char *)malloc(IBE_MPK_LEN);
    char *mpk = (char *)malloc(IBE_MPK_LEN);
    memcpy(global_mpk, payload, IBE_MPK_LEN);
    memcpy(mpk, payload+IBE_MPK_LEN, IBE_MPK_LEN);
    IBEPublicParameters *mpk_sp = &mpk;
    IBEPublicParameters *global_sp = &global_mpk;

    /* save global PP */
    put_mpk_fp(GLOBAL_MPK_FILENAME, global_sp, IBE_MPK_LEN);

    /* save domain PP */
    user::User *user= target->get_user_ptr();
    char *server_id = user_get_id(user)->father_node->id;
    GENERATE_MPK_FILENAME(server_id,strlen(server_id))
    put_mpk_fp(mpk_filename, mpk_sp, IBE_MPK_LEN);
    FREE_MPK_FILENAME;
    
    /* save mpk len */
    long mpk_len = length/2;
    FILE *mpk_len_fp = fopen(MPK_LEN_FILENAME, "wb");
    fwrite(&mpk_len, sizeof(mpk_len), 1, mpk_len_fp);
    fclose(mpk_len_fp);

    if(length!=IBE_MPK_LEN+IBE_MPK_LEN)
    {
        Error("handle mpk error");
        goto end;
    }
    
    rtn = 1;
end:
    return rtn;
}

int handle_try_mes(Packet *target)
{
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    int sign_len = length-IBE_MPK_LEN;
    char *payload = p->get_payload();
    char *mpk = (char *)malloc(IBE_MPK_LEN);
    memcpy(mpk, payload, IBE_MPK_LEN);
    IBEPrivateKey *ibe_mpk = &mpk;

    /* save the node's mpk */
    char *rec_id = p->get_id();
    GENERATE_MPK_FILENAME(rec_id, strlen(rec_id))
    put_mpk_fp(mpk_filename, ibe_mpk, IBE_MPK_LEN);
    FREE_MPK_FILENAME;

    /* get global sP */
    IBEPublicParameters ss_mpk = NULL;
    get_mpk_fp(GLOBAL_MPK_FILENAME, &ss_mpk);

    /* verify */
    char *sign = (char *)malloc(sign_len);
    memcpy(sign, payload+IBE_MPK_LEN, sign_len);
    SignMesg *sig = sign_from_bytes(sign, sign_len, 0);
    if(strcmp(rec_id, sig->ID))
        Error("verify ID error");

    if(strcmp(mpk,sig->PP))
        Error("verify mpk error");

    if(!sig_verify(sig, ss_mpk))
        Error("verify sig error");

    fprintf(stderr, "verify done.\n");

    PacketCTX *send_ctx = new PacketCTX;
    AppPacket *send_packet = new AppPacket;

    GENERATE_SIGN_LEN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id)) 
    FILE *fp1; 
    if((fp1=fopen(filename_len_sign,"rb"))==NULL)
    {
        interface::IUI::error("file cannot open \n");  
    }
    int send_sign_len;
    std::fread(&send_sign_len, sizeof(send_sign_len), 1, fp1);
    fclose(fp1);
    FREE_SIGN_LEN_FILENAME;

    GENERATE_SIGN_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id))
    char *send_sign = (char*)malloc(send_sign_len);
    FILE *fp_sign;
	if((fp_sign=fopen(filename_sign,"rb+"))==NULL)
	{
		interface::IUI::error("file cannot open \n");  
	}
	if(!fread(send_sign, 1, send_sign_len, fp_sign))
	{
		printf("error in read file \n");
		throw std::exception();
	}
    fclose(fp_sign);
    FREE_SIGN_FILENAME;

    IBEPublicParameters send_mpk = NULL;

    if(ctx->get_dest_id()->father_node!=nullptr)
    {
        GENERATE_MPK2_FILENAME(ctx->get_dest_id()->father_node->id, strlen(ctx->get_dest_id()->father_node->id))
        get_mpk_fp(mpk2_filename, &send_mpk);
        FREE_MPK2_FILENAME;
    }
    else
    {
        GENERATE_MPK2_FILENAME(ctx->get_dest_id()->id, strlen(ctx->get_dest_id()->id))
        get_mpk_fp(mpk2_filename, &send_mpk);
        FREE_MPK2_FILENAME;
    }

    char *send_payload = (char *)malloc(send_sign_len+IBE_MPK_LEN);
    memcpy(send_payload, send_mpk, IBE_MPK_LEN);
    memcpy(send_payload+IBE_MPK_LEN, send_sign, send_sign_len);

    send_packet->set_type(TRY_HANDLE_TYPE);
    send_packet->set_length(send_sign_len+IBE_MPK_LEN);
    send_packet->set_payload (send_payload);

    send_ctx->set_phase (SEND_APP_PACKET);
    send_ctx->set_payload_app (send_packet);

     if(0 == target->packet_send(send_ctx)) {
        Error("send the p error");
        goto end;
    }

    rnt = 1;

end:
    return rnt;
}

int handle_try_res(Packet *target)
{
    int rnt = 0;
    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    int sign_len = length-IBE_MPK_LEN;
    char *payload = p->get_payload();
    char *mpk = (char *)malloc(IBE_MPK_LEN);
    memcpy(mpk, payload, IBE_MPK_LEN);
    IBEPublicParameters *mpk_sp = &mpk;

    char *rec_id = p->get_id();

    GENERATE_MPK_FILENAME(rec_id, strlen(rec_id))
    put_mpk_fp(mpk_filename, mpk_sp, IBE_MPK_LEN);
    FREE_MPK_FILENAME;

    /* 获取顶级域的sP */
    IBEPublicParameters ss_mpk = NULL;
    get_mpk_fp(GLOBAL_MPK_FILENAME, &ss_mpk);

    char *sign = (char *)malloc(sign_len);
    memcpy(sign, payload+IBE_MPK_LEN, sign_len);
    SignMesg *sig = sign_from_bytes(sign, sign_len, 0);

    if(strcmp(rec_id, sig->ID))
    {
        Error("verify ID error");
        goto end;
    }
    if(strcmp(mpk,sig->PP))
    {
        Error("verify mpk error");
        goto end;
    }
    if(!sig_verify(sig, ss_mpk))
    {
        Error("verify sig error");
        goto end;
    }
    fprintf(stderr, "verify done.\n");
    rnt = 1;
end:
    return rnt;
}

int handle_get_Intkey(Packet *target)
{
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    char *message = p->get_payload();

    char *rec_id = p->get_id();
    GENERATE_INTKEY_FILENAME(rec_id, strlen(rec_id))
    FILE *fp;
    if((fp=fopen(filename_key,"wb+"))==NULL)
    {
        interface::IUI::error("file cannot open \n");  
    }
    std::fwrite(message, 1,  length, fp);
    fclose(fp);
    FREE_INTKEY_FILENAME;

#ifdef DEBUG
    interface::IUI::print("get Intkey done");
#endif

    rnt=1;
    return rnt;
}

int handle_get_Iotkey(Packet *target)
{
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();
    char *message = p->get_payload();
    IOTKey *key = new IOTKey();
    key = key_from_bytes(message);
    long key_time = *(long *)key->time;
    long key_duration = *(long *)key->duration;
    char sm4_key[SM4_KEY_LEN];
    memcpy(sm4_key, key->sm4key, SM4_KEY_LEN);

    time_t t = time(0);
    long time = (long)t;
    if(time-key_time<=key_duration)
    {
        interface::IUI::print("IotKey can be used \n");
        char *rec_id = p->get_id();
        GENERATE_IOTKEY_FILENAME(rec_id, strlen(rec_id))
        FILE *fp;
        if((fp=fopen(filename_key,"wb+"))==NULL)
        {
            interface::IUI::error("file cannot open \n");  
        }
        std::fwrite(message, 1,  length, fp);
        fclose(fp);
        FREE_IOTKEY_FILENAME;
    }
    else
    {
        interface::IUI::error("IotKey has expired \n");
    }
    
    
#ifdef DEBUG
    interface::IUI::print("get Iotkey done");
#endif

    rnt=1;
    return rnt;
}

int handle_init_message_1(Packet *target)
{
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();

    char *message = p->get_payload();
    int id_len;
    get_int(message, &id_len);

    message += 4;
    char *id = (char *)std::malloc(id_len+1);
    id[id_len] = '\0';
    memcpy(id, message, id_len);

    // check if it is necessary to insert the number
    init::Initializer *initializer = user_get_init(target->get_user_ptr());
    
    bool init_is_run = true;     // used to trigger the initializer
    if(!initializer)
    {
        init_is_run = false;
        initializer = init_new(target);
    }

    auto numbers = init_get_numbers(initializer);

    bool need_to_insert = true;
    ID *tmp_id = nullptr;
    for(auto elem : *(numbers))
    {
        tmp_id = elem.first;
        if(id_len==tmp_id->length
            && 0==strncmp(id, tmp_id->id, id_len))
        {/* there has been a value corresponding to this ID */
            need_to_insert = false;
            break;
        }
    }

    if(need_to_insert)
    {
        ID *insert_id = NULL;
        for(auto tmp_id : *(init_get_user_ids(initializer)))
        {
            if(id_len==tmp_id->length
                && 0==strncmp(id, tmp_id->id, id_len))
            {/* there is an ID correspond to this string */
                insert_id = tmp_id;
                break;
            }
        }

        if(insert_id)
        {
#ifdef DEBUG 
            Debug("need to insert");
#endif
            // insert the number 
            message += id_len;
            BIGNUM *bn = NULL;
            if(!BN_str2bn(&bn, message))
            {
                Error("cannot convert string to bn");
            }

            (*numbers)[insert_id] = bn;
        }
        
    }


#ifdef DEBUG
    interface::IUI::print("receive message done");
#endif

    // [IMPORTANT]
    // trigger the initializer
    if(!init_is_run)
    {
        init_run(initializer);
    }

    rnt=1;
    return rnt;
}


int handle_init_message_2(Packet *target)
{
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();

    char *message = p->get_payload();
    char *id = NULL;
    char *pPub1 = NULL;
    char *pPub2 = NULL;
    int id_len, len_pPub1, len_pPub2;
    
    
    get_int(message, &id_len);
    get_int(message+4, &len_pPub1);
    get_int(message+8, &len_pPub2);

    if(id_len+len_pPub1+len_pPub2+13 != length)
    {
        Error("the length of the packet is in wrong format");
    }

    message += 12;
    id = (char *)std::malloc(id_len+1);
    id[id_len] = '\0';
    memcpy(id, message, id_len);

    // check if it is necessary to insert the point
    init::Initializer *initializer = user_get_init(target->get_user_ptr());
    

    auto sp_points = init_get_sp_pub_points(initializer);
    auto sp2_points = init_get_sp2_pub_points(initializer);

    bool need_to_insert = true;
    ID *tmp_id = nullptr;
    for(auto elem : *sp_points)
    {
        tmp_id = elem.first;
        if(id_len==tmp_id->length
            && 0==strncmp(id, tmp_id->id, id_len))
        {/* there has been a value corresponding to this ID */
            need_to_insert = false;
            break;
        }
    }

    if(need_to_insert)
    {
        ID *insert_id = NULL;
        for(auto tmp_id : *init_get_user_ids(initializer))
        {
            if(id_len==tmp_id->length
                && 0==strncmp(id, tmp_id->id, id_len))
            {/* there is an ID correspond to this string */
                insert_id = tmp_id;
                break;
            }
        }

        if(insert_id)
        {
#ifdef DEBUG 
{
            std::ostringstream s;
            s << "the length of id: " << id_len << std::endl;
            s << "the length of p1: " << len_pPub1  << std::endl;
            s << "the length of p2: " << len_pPub2 << std::endl;
            Debug("need to insert");
            Debug(s.str());
}           
#endif
            // insert the number 
            pPub1 = message + id_len;
            pPub2 = pPub1 + len_pPub1;
            
            BN_CTX *ctx = BN_CTX_new();
            EC_POINT *pnt = ibe_EC_POINT_new();

            if(!ibe_str2ec(pPub1, pnt, ctx))
            {
                Error("cannot convert string to EC point");
            }

            (*sp_points)[insert_id] = pnt;

            // malloc a new space for the pPub2 in case it will 
            // be freed somewhere 
            point_t *point2 = NULL;
            if(!ibe_point_from_octets(&point2, pPub2) || !ibe_point_is_on_curve(point2))
            {
                Error("cannot convert pPub2 from string");
            }
#ifdef DEBUG 
            {
                Debug("the point inserted is on the curve");
            }
#endif
            
            (*sp2_points)[insert_id] = point2;

            BN_CTX_free(ctx);        

        }
        
    }


#ifdef DEBUG
    interface::IUI::print("receive message done");
#endif

    rnt=1;
    return rnt;
}


int handle_init_message_3(Packet *target)
{
    int rnt = 0;

    PacketCTX *ctx = target->get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int length = p->get_length();

    char *message = p->get_payload();
    int id_len;
    get_int(message, &id_len);

    message += 4;
    char *id = (char *)std::malloc(id_len+1);
    id[id_len] = '\0';
    memcpy(id, message, id_len);

    // check if it is necessary to insert the point
    init::Initializer *initializer = user_get_init(target->get_user_ptr()); 
    

    auto sq_points = init_get_sq_pub_points(initializer);

    bool need_to_insert = true;
    ID *tmp_id = nullptr;
    for(auto elem : *sq_points)
    {
        tmp_id = elem.first;
        if(id_len==tmp_id->length
            && 0==strncmp(id, tmp_id->id, id_len))
        {/* there has been a value corresponding to this ID */
            need_to_insert = false;
            break;
        }
    }

    if(need_to_insert)
    {
        ID *insert_id = NULL;
        for(auto tmp_id : *init_get_user_ids(initializer))
        {
            if(id_len==tmp_id->length
                && 0==strncmp(id, tmp_id->id, id_len))
            {/* there is an ID correspond to this string */
                insert_id = tmp_id;
                break;
            }
        }

        if(insert_id)
        {
#ifdef DEBUG 
            Debug("need to insert");
#endif
            // insert the number 
            message += id_len;
            
            BN_CTX *ctx = BN_CTX_new();
            EC_POINT *pnt = ibe_EC_POINT_new();

            if(!ibe_str2ec(message, pnt, ctx))
            {
                Error("cannot convert string to bn");
            }

            (*sq_points)[insert_id] = pnt;
            BN_CTX_free(ctx);

        }
        
    }


#ifdef DEBUG
    interface::IUI::print("receive message done");
#endif

    rnt=1;
    return rnt;
}



void Packet::handle_ap() 
{

    if(get_ctx()->get_phase() != RECV_APP_PACKET) {
        Error("call wrong function");
    }

    PacketCTX *ctx = get_ctx();
    AppPacket *p = ctx->get_payload_app();
    int type = p->get_type();
    int res = 0;

    switch (type)
    {
        case PLAIN_MESSAGE_TYPE:
            res = handle_m(this);
            break;
        
        case PRIVATE_KEY_REQUEST_TYPE:
            res = handle_sk_request(this);
            break;
        
        case PRIVATE_KEY_RESPONSE_TYPE:
            res = handle_sk_response(this);
            break;
        
        case SESSION_KEY_REQUEST_TYPE:
            res = handle_session_request(this);
            break;

        case SESSION_KEY_ACK_TYPE:
            res = handle_session_ack(this);
            break;

        case SESSION_KEY_FINAL_TYPE:
            res = handle_session_final(this);
            break;

        case IBE_MES_TYPE:
            res = handle_message(this);
            break;

        case MPK_REQUEST_TYPE:
            res = handle_mpk_request(this);
            break;

        case MPK_RESPONSE_TYPE:
            res = handle_mpk_response(this);
            break;

        case TRY_MES_TYPE:
            res = handle_try_mes(this);
            break;
        
        case TRY_HANDLE_TYPE:
            res = handle_try_res(this);
            break;

        case INT_KEY_TYPE:
            res = handle_get_Intkey(this);
            break;

        case IOT_KEY_TYPE:
            res = handle_get_Iotkey(this);
            break;

        case INIT_MESSAGE_1:
            res = handle_init_message_1(this);
            break;

        case INIT_MESSAGE_2:
            res = handle_init_message_2(this);
            break;

        case INIT_MESSAGE_3:
            res = handle_init_message_3(this);
            break;
        
        default:
            Error("the p type is invalid");
            break;
    }

    if(!res)
    {
        Error("handle the packet error");
    }
    
    ctx->set_phase (RECV_DONE);
}
