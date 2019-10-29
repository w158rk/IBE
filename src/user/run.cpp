#include<user.hpp>

using namespace user;

int User::run()
{
    // run the listener
    m_comm_ptr->socket_main();

    // run the ui
    m_ui_ptr->run();
}