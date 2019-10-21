#ifndef PACKET_HPP
#define PACKET_HPP

#include<interface.hpp>
#include<utils.h>
#include<crypto.h>

namespace packet {

    class Packet : public interface::IPacket 
    {
    
    public :
        int packet_handle(PacketCTX *ctx);    
        int packet_send(PacketCTX *ctx);    
        void packet_handle();    
        void packet_send();    

        GET_AND_SET(interface::IUI *, ui_ptr)
        GET_AND_SET(interface::IUser *, user_ptr)
        GET_AND_SET(interface::IComm *, comm_ptr)
        GET_AND_SET(PacketCTX *, ctx)

        unsigned char sm4key[SM4_KEY_LEN];

    private:
        DECLARE_MEMBER(PacketCTX *, ctx)
        DECLARE_MEMBER(interface::IUser *, user_ptr)
        DECLARE_MEMBER(interface::IComm *, comm_ptr)
        DECLARE_MEMBER(interface::IUI *, ui_ptr)

        void handle_ap();
        void handle_dec();
        void handle_sp();
        void handle_verify();

        void send_ap();
        void send_enc();
        void send_sign();
        void send_sp();

    };

}

#endif