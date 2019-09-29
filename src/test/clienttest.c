#include "config.h"
#include "comm.h"

int main() {
    ID_init();
    socket_main(&client, CLIENT_LISTEN_PORT);
}
