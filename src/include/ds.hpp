#ifndef DS_HPP 
#define DS_HPP

#include <ds.h>


typedef struct app_packet {
    app_packet() : payload(nullptr) {}
    char head[APP_HEAD_LEN];
    char *payload;
} AppPacket;

typedef struct sec_packet {
    sec_packet() 
    {
        payload.data = nullptr;
    }
    char head[SEC_HEAD_LEN];
    union payload1 {
        char *data;
        AppPacket *appPacket;
    } payload;
    char signature[SIGN_LEN];
} SecPacket;


typedef struct packet_ctx{
    packet_ctx() : src_id(nullptr), dest_id(nullptr), 
                    mpk(nullptr), sk(nullptr), key(nullptr) 
    {
        payload.appPacket = nullptr;
    }
    enum state phase;
    union payload2 {
        AppPacket *appPacket;
        SecPacket *secPacket;
    } payload;
    
    ID *src_id; 
    ID *dest_id;
    
    IBEPublicParameters mpk;
    IBEPrivateKey sk;  

   char *sm4_key[16];

   char * key;

} PacketCTX;


#endif