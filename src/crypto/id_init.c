#include <ds.h>
#include "config.h"
#include "comm.h"

ID server;
ID client;

void ID_init()
{
    server.id = SERVER_ID;
    server.length = 1;
    server.ip = SERVER_IP_ADDRESS;
    server.port =SERVER_LISTEN_PORT;
    //server.father_node = &server;
    client.id = CLIENT_ID;
    client.length = 2;
    client.father_node = &server;
}