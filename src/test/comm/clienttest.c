#include "../comm/client_server.h"
#include "../comm/server.h"

int main() {

    socket_main(CLIENT_ID, CLIENT_ID_LEN, CLIENT_LISTEN_PORT);
}