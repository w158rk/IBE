#include "config.h"
#include "comm.h"

int main() {
    ID_init();
    socket_main(&server, SERVER_LISTEN_PORT);
}
