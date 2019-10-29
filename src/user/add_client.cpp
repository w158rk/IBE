#include<user.hpp>
#include<packet.hpp>

using namespace user;

void User::add_client(interface::IComm *comm)
{

    if(comm==nullptr)
    {
        throw UserException("The comm used by add_client is null");
    }

    // add the comm into the comm set for the current linked client 
    client_comms.insert(comm);

    // create a packet 
    packet::Packet* p = new packet::Packet;
    client_packets.insert(p);

    // link the objects 
    comm->set_user_ptr(this);
    comm->set_packet_ptr(p);
    comm->set_ui_ptr(get_ui_ptr());

    p->set_user_ptr(this);
    p->set_comm_ptr(comm);
    p->set_ui_ptr(get_ui_ptr());

}