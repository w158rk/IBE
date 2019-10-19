#include<iostream>
#include<app.hpp>
#include<config.h>

int main() 
{
    ID client_id;
    client_id.id = CLIENT_ID;
    client_id.length = CLIENT_ID_LEN;

    app::Client client(std::string(CLIENT_IP_ADDRESS), CLIENT_LISTEN_PORT, &client_id);
    client.run();

}