#include "config.h"
#include "comm.h"

int main() {
    socket_main(SERVER_ID, SERVER_ID_LEN, SERVER_LISTEN_PORT);
}