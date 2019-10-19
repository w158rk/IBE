#ifndef INTERFACE_H
#define INTERFACE_H

#include<ds.h>
#include<string>

namespace interface 
{

    class IPacket 
    {

    public:
        virtual int packet_send(PacketCTX *ctx) = 0;
        virtual int packet_handle(PacketCTX *ctx) = 0;

        virtual ~IPacket() = default;

    };

    class IComm 
    {

    public:
        virtual int send(const void *vptr, size_t n) = 0;
        virtual int connect_to_server(char* ip_addr, int port) = 0;
        
        virtual void socket_main() = 0;
        virtual void file_main() = 0;

        virtual ~IComm() = default;

    };

    class IUser 
    {

    public:
        virtual ID *get_id() = 0;
        virtual std::string get_ip_address() = 0;
        virtual int get_port() = 0;

        virtual int run_send_message(char *dest_ip, 
				        			int dest_port,
						        	ID *dest_id) = 0;

        virtual ~IUser() = default;

    };

    class IUI
    {

    public:
        void virtual run() = 0;
        virtual ~IUI() = default;
    };
    
} 

#endif