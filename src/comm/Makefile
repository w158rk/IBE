CLIENT_ROOT = Client
SERVER_ROOT = Server
DEBUG = -D__DEBUG__

ifdef fifo
	MODE = -D__FIFO_MODE__
else
	MODE = -D__SOCKET_MODE__
endif

all : ${CLIENT_ROOT}/client ${SERVER_ROOT}/server
.PHONY : all

# client part
${CLIENT_ROOT}/client : ${CLIENT_ROOT}/client.o ${CLIENT_ROOT}/client_connection.o ${CLIENT_ROOT}/client_core.o client_server.o
	gcc -Wall -o ${CLIENT_ROOT}/client ${CLIENT_ROOT}/client.o ${CLIENT_ROOT}/client_connection.o ${CLIENT_ROOT}/client_core.o client_server.o -lcurses
${CLIENT_ROOT}/client.o : ${CLIENT_ROOT}/client.c ${CLIENT_ROOT}/client.h client_server.h
	gcc -Wall -o ${CLIENT_ROOT}/client.o -c ${CLIENT_ROOT}/client.c ${DEBUG} ${MODE}
${CLIENT_ROOT}/client_connection.o : ${CLIENT_ROOT}/client_connection.c client_server.h
	gcc -Wall -o ${CLIENT_ROOT}/client_connection.o -c ${CLIENT_ROOT}/client_connection.c ${DEBUG}
${CLIENT_ROOT}/client_core.o : ${CLIENT_ROOT}/client_core.c client_server.h
	gcc -Wall -o ${CLIENT_ROOT}/client_core.o -c ${CLIENT_ROOT}/client_core.c ${DEBUG} -I/user/include

# server part
${SERVER_ROOT}/server : ${SERVER_ROOT}/server.o ${SERVER_ROOT}/server_connection.o ${SERVER_ROOT}/server_core.o client_server.o
	gcc -Wall -o ${SERVER_ROOT}/server ${SERVER_ROOT}/server.o ${SERVER_ROOT}/server_connection.o ${SERVER_ROOT}/server_core.o client_server.o -L/usr/lib/mysql -lmysqlclient
${SERVER_ROOT}/server.o : ${SERVER_ROOT}/server.c ${SERVER_ROOT}/server.h client_server.h
	gcc -Wall -o ${SERVER_ROOT}/server.o -c ${SERVER_ROOT}/server.c ${DEBUG} ${MODE}
${SERVER_ROOT}/server_connection.o : ${SERVER_ROOT}/server_connection.c client_server.h
	gcc -Wall -o ${SERVER_ROOT}/server_connection.o -c ${SERVER_ROOT}/server_connection.c ${DEBUG}
${SERVER_ROOT}/server_core.o : ${SERVER_ROOT}/server_core.c client_server.h
	gcc -Wall -o ${SERVER_ROOT}/server_core.o -c ${SERVER_ROOT}/server_core.c -I/usr/include/mysql ${DEBUG}


# common part
client_server.o : client_server.c client_server.h
	gcc -Wall -o client_server.o -c client_server.c ${DEBUG}
