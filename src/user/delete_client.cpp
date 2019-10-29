#include<user.hpp>
#include<packet.hpp>

using namespace user;

void User::delete_client(interface::IComm *comm)
{

    if(comm==nullptr)
    {
        throw UserException("The comm used by add_client is null");
    }

    client_packets.erase(comm->get_packet_ptr());
    delete comm->get_packet_ptr();

    client_comms.erase(comm);
    delete comm;

}