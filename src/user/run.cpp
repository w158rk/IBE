#include<user.hpp>
#include "user_lcl.hpp"

using namespace user;

int User::run()
{
    // run the listener

    m_comm_ptr->socket_main();

    // run the ui
    m_ui_ptr->run();
}


void User::run_init_server()
{
    // run the listener
    comm_socket_listener_run(get_comm_ptr());

}

void User::run_init_client()
{
    
    m_comm_ptr->socket_main();
    sys_init();

}