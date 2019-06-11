/**
 * This file deals with the connection between client and server
 * It contains a funciton to establish a connection and remove a connection
 */
#include "../client_server.h"

/**
 * This function establishs a connection with a fifo server
 * read_file will be set to point to the FILE for read
 * write_file will be set to point to the FILE for write
 * @return -1 for failure, others for success
 */
int connect_fifo_server(char* server_public_fifo_name, FILE** read_file, FILE** write_file)
{
	int server_fifo_fd, client_fifo_fd;
	pid_t client_pid;
	char client_fifo_name[256];
	char server_fifo_name[256];
	char content[BUFFER_SIZE];

	// open the server public fifo
	server_fifo_fd = open(server_public_fifo_name, O_WRONLY);
	if(server_fifo_fd == -1)
	{
		fprintf(stderr, "sorry can't connect to the server\n");
		return -1;
	}

	// prepare the client fifo and set the read_file
	client_pid = getpid();
	snprintf(client_fifo_name, sizeof(client_fifo_name), "/tmp/client_%d_fifo", client_pid);
	unlink(client_fifo_name); // remove possible existed file
	if(mkfifo(client_fifo_name, 0777) == -1)
	{
		fprintf(stderr, "sorry, can't create %s\n", client_fifo_name);
		return -1;
	}
	client_fifo_fd = open(client_fifo_name, O_RDONLY | O_NONBLOCK);
	if(client_fifo_fd == -1)
	{
		fprintf(stderr, "sorry can't open the client fifo %s\n", client_fifo_name);
		return -1;
	}

	// turn off non-blocking mode
	if(fcntl(client_fifo_fd, F_SETFL, fcntl(client_fifo_fd, F_GETFL) & ~O_NONBLOCK) == -1)
	{
		fprintf(stderr, "can't turn off non-blocking mode for client fifo\n");
		return -1;
	}
	 
	*read_file = fdopen(client_fifo_fd, "r");
	if(*read_file == NULL)
	{
		fprintf(stderr, "convertion from  client fifo fd to FILE struct has error: %s\n", strerror(errno));
		return -1;
	}

	// send a establish connection request
	snprintf(content, sizeof(content), "%d\n%d\n", ESTABLISH_CONNECTION_REQUEST, client_pid);
	write(server_fifo_fd, content, sizeof(char) * strlen(content)); 

	// read server response
	// get response identity
	if(Fgets(content, sizeof(content), *read_file) == NULL)
	{
		fprintf(stderr, "can't get server establish connection response\n");
		return -1;
	}
	if(atoi(content) != ESTABLISH_CONNECTION_RESPONSE)
	{
		fprintf(stderr, "expect a ESTABLISH_CONNECTION_RESPONSE but get %s\n", content);
		exit(-1);
	}
	// get server subprocess id
	if(read_line(content, sizeof(content), *read_file, false) == NULL)
	{
		fprintf(stderr, "can't get server subprocess id\n");
		return -1;
	}
	int server_subprocess_id = atoi(content);

	// close the server public fifo, prepare the server private fifo and set the write_file
	if(close(server_fifo_fd) == -1)
	{
		fprintf(stderr, "can't close server public fifo\n");
		return -1;
	}
	snprintf(server_fifo_name, sizeof(server_fifo_name), "/tmp/server_%d_fifo", server_subprocess_id);
	if((server_fifo_fd = open(server_fifo_name, O_WRONLY)) == -1)
	{
		fprintf(stderr, "can't open server fifo %s\n", server_fifo_name);
		return -1;
	}
	if((*write_file = fdopen(server_fifo_fd, "w")) == NULL)
	{
		fprintf(stderr, "convertion from server filo fd to FILE struct has error: %s\n", strerror(errno));
		return -1;
	}
	
	// send establish connection confirm
	snprintf(content, sizeof(content), "%d\n", ESTABLISH_CONNECTION_ACK);
	write(server_fifo_fd, content, sizeof(char) * strlen(content));
	return 0;
}


int disconnect_fifo_server(FILE* read_file, FILE* write_file)
{
	if(fclose(write_file) == EOF)
	{
		fprintf(stderr, "close the write file occurs an error: %s\n", strerror(errno));
		return -1;
	}
	if(fclose(read_file) == EOF)
	{
		fprintf(stderr, "close the read file occurs an error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int connect_socket_server(char* ip_addr, int port, FILE** read_file, FILE** write_file)
{
	int socket_fd;
	struct sockaddr_in server_addr;

	if((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, "can't create client socket\n");
		return -1;
	}

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, ip_addr, &server_addr.sin_addr);
	
	if(connect(socket_fd, (SA *) &server_addr, sizeof(server_addr)) == -1)
	{
		fprintf(stderr, "can't connect to server socket\n");
		return -1;
	}

	if((*read_file = fdopen(socket_fd, "r+")) == NULL)
	{
		fprintf(stderr, "convertion from connected socket fd to FILE struct has error\n");
		return -1;
	}
	*write_file = *read_file;

	return 0;
}

int disconnect_socket_server(FILE* read_file, FILE* write_file)
{
	// socket is duplex, so read_file and write_file is the same file
	if(fclose(read_file) == EOF)
	{
		fprintf(stderr, "close the read file occurs an error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}
