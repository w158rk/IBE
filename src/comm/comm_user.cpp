#include <user.hpp>
#include "comm_lcl.hpp"

using namespace comm;
using namespace user;

int comm::user_get_port(Comm* comm)
{
    return comm->get_user_ptr()->get_port();
}

void comm::user_delete_client(Comm *comm)
{
    comm->get_user_ptr()->delete_client(comm);
}

void comm::user_set_thread(Comm *comm, std::thread *lsn)
{
    comm->get_user_ptr()->set_thread(lsn);
}

void comm::user_add_client(Comm *comm, User *user)
{
	user->add_client(comm);
}

void comm::user_add_thread(User *user, std::thread *lsn)
{
	user->add_thread(lsn);
}

ID* comm::user_get_id(User *user)
{
    return user->get_id();
}

