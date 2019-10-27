#include <user.hpp>

void bind_objects(interface::IUser& user, 
                    interface::IComm& comm, 
                    interface::IPacket& packet, 
                    interface::IUI& uinterface,
                    char *err_sig)
{
    user.set_err_sig(err_sig);
    user.set_packet_ptr(&packet);
    user.set_comm_ptr(&comm);
    user.set_ui_ptr(&uinterface);

    comm.set_err_sig(err_sig);
    comm.set_user_ptr(&user);
    comm.set_packet_ptr(&packet);

    packet.set_user_ptr(&user);
    packet.set_comm_ptr(&comm);
    packet.set_ui_ptr(&uinterface);

    uinterface.set_user_ptr(&user);
}