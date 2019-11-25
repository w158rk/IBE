#ifndef COMM_LCL_HPP 
#define COMM_LCL_HPP 

#include <comm.hpp>

extern "C"{
#include "comm_lcl.h"
}

/**
 * interface functions 
 */
namespace comm
{

    int user_get_port(comm::Comm* comm);
    ID *user_get_id(user::User *);

    void user_add_client(comm::Comm *comm, user::User *user);
    void user_delete_client(comm::Comm *comm);
    void user_add_thread(user::User *, std::thread *lsn);
    void user_set_thread(comm::Comm *, std::thread *lsn);

}

#endif