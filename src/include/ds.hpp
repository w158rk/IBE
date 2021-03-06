#ifndef DS_HPP 
#define DS_HPP

// extern "C" 
// {
// # include <string.h>
// }

#include <ds.h>
#include<utils.h>
#include<crypto.h>
#include<string>


enum state {
    SEND_APP_PACKET,
    SEND_SIGN,
    SEND_ENC,
    SEND_SEC_PACKET,
    SEND_DONE,

    RECV_DONE,
    RECV_APP_PACKET,
    RECV_VERIFY,
    RECV_DEC,
    RECV_SEC_PACKET,
};

class AppPacket 
{

public:
    AppPacket();
    ~AppPacket();

    GET_AND_SET(char *, payload);
    GET_AND_SET(char *, head);
    GET_AND_SET(char *, id);

    static AppPacket *from_bytes(char *);
    char *to_bytes();

    int get_length();
    int get_type();
    void set_length(int);
    void set_type(int);

private:
    char m_head[APP_HEAD_LEN]; 
    char m_id[ID_LEN_MAX];
    bool m_fhead;
    bool m_fid;
    DECLARE_MEMBER(char *, payload);

};

// typedef struct app_packet {
//     char head[APP_HEAD_LEN];
//     char *payload;
// } AppPacket;

class SecPacket 
{

private:
    union payload 
    {
        char *data;
        AppPacket *appPacket;        
    };

    DECLARE_MEMBER(union payload, payload)
    char m_head[SEC_HEAD_LEN];
    char m_signature[IBE_SIGN_LEN];
    bool m_fhead;
    bool m_fsignature;



public: 
    SecPacket();
    ~SecPacket();
   
    GET_AND_SET(char *, payload_byte)
    GET_AND_SET(AppPacket *, payload_app)
    GET_AND_SET(char *, head);
    GET_AND_SET(char *, signature);

    int get_length();
    int get_type();
    char *get_id();
    void set_length(int);
    void set_type(int);
    void set_id(char *);

    static SecPacket *from_bytes(char *);
    char *to_bytes();

};

// typedef struct sec_packet {
//     sec_packet() 
//     {
//         payload.data = nullptr;
//     }
//     char head[SEC_HEAD_LEN];
//     union payload1 {
//         char *data;
//         AppPacket *appPacket;
//     } payload;
//     char signature[SIGN_LEN];
// } SecPacket;


class PacketCTX
{
private: 


    DECLARE_MEMBER(ID *, src_id)
    DECLARE_MEMBER(ID *, dest_id)
    DECLARE_MEMBER(IBEPublicParameters*, mpk)
    DECLARE_MEMBER(IBEPrivateKey*, sk)

    union payload 
    {
        AppPacket *appPacket;
        SecPacket *secPacket;
    };

    DECLARE_MEMBER(union payload, payload)

    /**
     * packet process context
     */


    DECLARE_MEMBER(enum state, phase)

public:

    PacketCTX();
    ~PacketCTX();

    GET_AND_SET(ID *, src_id)
    GET_AND_SET(ID *, dest_id)
    GET_AND_SET(IBEPublicParameters*, mpk)
    GET_AND_SET(IBEPrivateKey*, sk)
    GET_AND_SET(AppPacket*, payload_app)
    GET_AND_SET(SecPacket*, payload_sec)
    GET_AND_SET(enum state, phase)


};

class RootException : std::exception 
{
public:
    RootException(std::string message)
    {
        set_message(message);
    }
    RootException() = default;
    ~RootException() = default;

    GET_AND_SET(std::string, message)
    virtual std::string what(){}
};

// typedef struct packet_ctx{
//     packet_ctx() : src_id(nullptr), dest_id(nullptr), 
//                     mpk(nullptr), sk(nullptr), key(nullptr) 
//     {
//         payload.appPacket = nullptr;
//     }
//     enum state phase;
//     union payload2 {
//         AppPacket *appPacket;
//         SecPacket *secPacket;
//     } payload;
    
//     ID *src_id; 
//     ID *dest_id;
    
//     IBEPublicParameters mpk;
//     IBEPrivateKey sk;  

//    char sm4_key[16];

//    char key;

// } PacketCTX;


#endif