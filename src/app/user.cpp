#include<iostream>
#include<app.hpp>

extern "C" {
    #include<comm.h>
}

using namespace app;

User::User(std::string ip_address, int port, ID* id)
{
    set_ip_address(ip_address);
    set_port(port);
    set_id(id);
}

int User::run()
{
    // run the listener
    m_comm_ptr->socket_main();

    // run the ui
    m_ui_ptr->run();
}


User::~User() 
{
    
}