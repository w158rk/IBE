#include<iostream>

#include<user.hpp>
#include<comm.hpp>
#include<ui.hpp>
#include<packet.hpp>

#include<config.h>


int main() 
{
    char err_sig;
    ID server_id;
    server_id.id = SERVER_ID;
    server_id.length = SERVER_ID_LEN;

    user::Server server(std::string(SERVER_IP_ADDRESS), SERVER_LISTEN_PORT, &server_id);
    server.set_err_sig(&err_sig);

    packet::Packet *packet = new packet::Packet();

    comm::Comm comm(packet, &(interface::IUser&)server);
    comm.set_err_sig(&err_sig);
    
    ui::UInterface* uinterface = new ui::UInterface();

    packet->set_comm_ptr(&comm);
    uinterface->set_user_ptr(&(interface::IUser&)server);
    server.set_ui_ptr(dynamic_cast<interface::IUI*>(uinterface));
    server.set_comm_ptr(dynamic_cast<interface::IComm*>(&comm));

    server.set_packet_ptr(packet);

    server.run();

}