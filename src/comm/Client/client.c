/**
 * This file is the implementaion of client
 */
#include "../client_server.h"
#include "client.h"

int fifo_client_run();
int socket_client_run();

int main()
{
	#ifdef __FIFO_MODE__
	if(fifo_client_run() == -1)
	{
		fprintf(stderr, "fifo client run error\n");
		exit(-1);
	}
	#elif defined __SOCKET_MODE__
	if(socket_client_run() == -1)
	{
		fprintf(stderr, "socket client run error\n");
		exit(-1);
	}
	#endif

	return 0;
}

int fifo_client_run()
{
	FILE* read_file;
	FILE* write_file;
	if(connect_fifo_server(SERVER_PUBLIC_FIFO_NAME , &read_file, &write_file) == -1)
	{
		fprintf(stderr, "connect_fifo_server has an error\n");
		return -1;
	}

	if(run_client_core(read_file, write_file) == -1)
	{
		fprintf(stderr, "client core has error\n");
		exit(-1);
	}

	if(disconnect_fifo_server(read_file, write_file) == -1)
	{
		fprintf(stderr, "disconnect_fifo_server has an error\n");
		return -1;
	}

	return 0;
}

int socket_client_run()
{
	FILE* read_file;
	FILE* write_file;

	if(connect_socket_server(SERVER_IP_ADDRESS, SERVER_PORT, &read_file, &write_file) == -1)
	{
		fprintf(stderr, "connect_socket_server has an error\n");
		return -1;
	}

	if(run_client_core(read_file, write_file) == -1)
	{
		fprintf(stderr, "client core has error\n");
		exit(-1);
	}

	if(disconnect_socket_server(read_file, write_file) == -1)
	{
		fprintf(stderr, "disconnect_socket_server has an error\n");
		return -1;
	}

	return 0;
}
