#include "../client_server.h"


int create_listening_fifo(char* server_public_fifo_name, FILE** read_file)
{
	unlink(server_public_fifo_name); // remove possible existed file
	if(mkfifo(server_public_fifo_name, 0777) == -1)
	{
		fprintf(stderr, "can't create public fifo error: %s\n", strerror(errno));
		return -1;
	}

	int server_public_fifo_fd;
	if((server_public_fifo_fd = open(server_public_fifo_name, O_RDONLY | O_NONBLOCK)) == -1)
	{
		fprintf(stderr, "can't open server public fifo\n");
		return -1;	
	}

	// turn off non-blocking mode
	if(fcntl(server_public_fifo_fd, F_SETFL, fcntl(server_public_fifo_fd, F_GETFL) & ~O_NONBLOCK) == -1)
	{
		fprintf(stderr, "can't turn off non-blocking mode for server public fifo\n");
		return -1;
	}
	
	if((*read_file = fdopen(server_public_fifo_fd, "r")) == NULL)
	{
		fprintf(stderr, "convertion from server public fifo fd to FILE struct has error: %s\n", strerror(errno));
		return -1;
	}
	
	#ifdef __DEBUG__
	fprintf(stdout, "create listening fifo successfully\n");
	#endif
	
	return 0;
}

int close_listening_fifo(FILE* read_file)
{
	if(fclose(read_file) == EOF)
	{
		fprintf(stderr, "close public fifo error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int establish_client_server_fifo_connection(pid_t client_pid, FILE** read_file, FILE** write_file)
{
	pid_t server_pid;
	int server_fifo_fd, client_fifo_fd;
	char server_fifo_name[256];
	char client_fifo_name[256];
	char content[BUFFER_SIZE];

	// prepare the server fifo and set read_file
	server_pid = getpid();
	snprintf(server_fifo_name, sizeof(server_fifo_name), "/tmp/server_%d_fifo", server_pid);
	unlink(server_fifo_name);
	if(mkfifo(server_fifo_name, 0777) == -1)
	{
		fprintf(stderr, "can't create %s\n", server_fifo_name);
		return -1;
	}
	if((server_fifo_fd = open(server_fifo_name, O_RDONLY | O_NONBLOCK)) == -1)
	{
		fprintf(stderr, "can't open the server fifo %s\n", server_fifo_name);
		return -1;
	}
	// turn off non-blocking mode
	if(fcntl(server_fifo_fd, F_SETFL, fcntl(server_fifo_fd, F_GETFL) & ~O_NONBLOCK) == -1)
	{
		fprintf(stderr, "can't turn off non-blocking mode for server private fifo\n");
		return -1;
	}
	if((*read_file = fdopen(server_fifo_fd, "r")) == NULL)
	{
		fprintf(stderr, "convertion from server fifo fd to FILE struct has error\n");
		return -1;
	}

	// connect the client fifo and set write_file
	snprintf(client_fifo_name, sizeof(client_fifo_name), "/tmp/client_%d_fifo", client_pid);
	if((client_fifo_fd = open(client_fifo_name, O_WRONLY)) == -1)
	{
		fprintf(stderr, "can't open the client fifo %s\n", client_fifo_name);
		return -1;
	}
	if((*write_file = fdopen(client_fifo_fd, "w")) == NULL)
	{
		fprintf(stderr, "convertion from client fifo fd to FILE struct has error\n");
		return -1;
	}
	
	snprintf(content, sizeof(content), "%d\n%d\n", ESTABLISH_CONNECTION_RESPONSE, server_pid);
	write(client_fifo_fd, content, sizeof(char) * strlen(content));

	// receive client confirm
	Fgets(content, sizeof(content), *read_file);
	if(atoi(content) != ESTABLISH_CONNECTION_ACK)
	{
		fprintf(stderr, "expect a ESTABLISH_CONNECTION_ACK but get %s\n", content);
		exit(-1);
	}
	return 0;
}

/**
 * create a listening socket
 * @return socket file descriptor or -1 for error
 */
int create_listening_socket()
{
	int listen_fd;
	struct sockaddr_in server_addr;

	if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, "can't create a listening socket\n");
		return -1;
	}
	
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(SERVER_PORT);

	if(bind(listen_fd, (SA *)&server_addr, sizeof(server_addr)) == -1)
	{
		fprintf(stderr, "can't bind listening socket\n");
		return -1;
	}

	if(listen(listen_fd, LISTEN_BACKLOG) == -1)
	{
		fprintf(stderr, "can't listen on listening socket\n");
		return -1;
	}
	
	return listen_fd;
}
