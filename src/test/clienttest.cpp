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
    packet::Packet *packet = new packet::Packet();
    comm::Comm comm(packet, dynamic_cast<interface::IUser *>(&client));
    ui::UInterface* uinterface = new ui::UInterface();


    comm.set_err_sig(&err_sig);

    uinterface->set_user_ptr(&(interface::IUser&)client);

    packet->set_comm_ptr(&comm);
    packet->set_ui_ptr(uinterface);
    packet->set_user_ptr(&client);

    client.set_err_sig(&err_sig);
    client.set_ui_ptr(dynamic_cast<interface::IUI*>(uinterface));
    client.set_comm_ptr(dynamic_cast<interface::IComm*>(&comm));
    client.set_packet_ptr(packet);

    client.run();

}