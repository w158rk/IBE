#include "config.h"
#include "client.h"
#include "comm.h"

int main() {

    socket_main(CLIENT_ID, CLIENT_ID_LEN, CLIENT_LISTEN_PORT);
}