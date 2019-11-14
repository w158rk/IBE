#ifndef INTERFACE_H
#define INTERFACE_H

#include<ds.hpp>
#include<utils.h>
#include<string>
#include<thread>

namespace init{
    class Initializer;    
};

namespace interface 
{
    class IPacket;
    class IComm;
    class IUI;
    class IUser;

    class IPacket 
    {

    public:
        virtual int packet_send(PacketCTX *ctx) = 0;
        virtual int packet_handle(PacketCTX *ctx) = 0;

        virtual ~IPacket() = default;
        VIRTUAL_GET_AND_SET(IComm *, comm_ptr)
        VIRTUAL_GET_AND_SET(IUser *, user_ptr)
        VIRTUAL_GET_AND_SET(IUI *, ui_ptr)
    };

    class IComm 
    {

    public:
        virtual int send(const void *vptr, size_t n) = 0;
        virtual void connect_to_server(char* ip_addr, int port) = 0;
        
        virtual void socket_main() = 0;

        virtual ~IComm() = default;

        static void file_main(IUser *user, 
					std::FILE *read_file, 
					std::FILE *write_file); 

        VIRTUAL_GET_AND_SET(IPacket *, packet_ptr)
        VIRTUAL_GET_AND_SET(IUser *, user_ptr)
        VIRTUAL_GET_AND_SET(IUI *, ui_ptr)
        VIRTUAL_GET_AND_SET(std::FILE *, read_file)
        VIRTUAL_GET_AND_SET(std::FILE *, write_file)

    };

    class IUser 
    {

    public:
        virtual ID *get_id() = 0;
        virtual std::string get_ip_address() = 0;
        virtual int get_port() = 0;

        virtual void run_send_message(char *dest_ip, 
				        			int dest_port,
						        	ID *dest_id) = 0;
        virtual void send_init_message_1(char *buff, 
				        			int len,
						        	ID *dest_id) = 0;
        virtual void send_init_message_2(char *buff, 
				        			int len,
						        	ID *dest_id) = 0;
        virtual void send_init_message_3(char *buff, 
				        			int len,
						        	ID *dest_id) = 0;
        virtual void sys_init() = 0;

        virtual ~IUser() = default;

        VIRTUAL_GET_AND_SET(char *, err_sig)
        VIRTUAL_GET_AND_SET(IUI *, ui_ptr)
        VIRTUAL_GET_AND_SET(char *, mpk_filename)
        VIRTUAL_GET_AND_SET(char *, msk_filename)
        VIRTUAL_GET_AND_SET(IComm *, comm_ptr)
        VIRTUAL_GET_AND_SET(IPacket *, packet_ptr)
        VIRTUAL_GET_AND_SET(std::thread *, thread)
        VIRTUAL_GET_AND_SET(char *, sm4_key)
        VIRTUAL_GET_AND_SET(char *, msk_len_file)
        VIRTUAL_GET_AND_SET(char *, cfg_filename)
        VIRTUAL_GET_AND_SET(char *, mpk_len_file)
        VIRTUAL_GET_AND_SET(long, mpk_len)
        VIRTUAL_GET_AND_SET(long, msk_len)
        VIRTUAL_GET_AND_SET(long, sk_len)
        VIRTUAL_GET_AND_SET(init::Initializer*, initializer)

        virtual void add_client(IComm *comm) = 0;
        virtual void delete_client(IComm *comm) = 0;
        virtual void add_thread(std::thread *thread) = 0;
        virtual void delete_thread(std::thread *thread) = 0 ;
    };

    class IUI
    {

    public:
        void virtual run() = 0;
        static void print(std::string message);
        static void error(std::string message);
        static void debug(std::string message);
        static void print(char *message, int length);
        static void error(char *message, int length);
        static void debug(char *message, int length);
        virtual ~IUI() = default;
        VIRTUAL_GET_AND_SET(IUser *, user_ptr)
    };
    
} 

#endif