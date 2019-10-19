#include<iostream>
#include<config.h>

#include<user.hpp>
#include<comm.hpp>
#include<ui.hpp>
#include<packet.hpp>


int main() 
{
    char err_sig;
    ID server_id;
    server_id.id = SERVER_ID;
    server_id.length = SERVER_ID_LEN;

    ID client_id;
    client_id.id = CLIENT_ID;
    client_id.length = CLIENT_ID_LEN;
    client_id.father_node = &server_id;

    user::Client client(std::string(CLIENT_IP_ADDRESS), CLIENT_LISTEN_PORT, &client_id);
    client.set_err_sig(&err_sig);

    packet::Packet *packet = new packet::Packet();

    comm::Comm comm(packet, &(interface::IUser&)server);
    comm.set_err_sig(&err_sig);
    
    ui::UInterface* uinterface = new ui::UInterface();

    uinterface->set_user_ptr(&(interface::IUser&)server);
    client.set_ui_ptr(dynamic_cast<interface::IUI*>(uinterface));
    client.set_comm_ptr(dynamic_cast<interface::IComm*>(&comm));

    client.run();

}