/**
 * This file is the implementaion of server
 */
#include "../client_server.h"
#include "server.h"

#define SYSTEM_LOG "/tmp/railway_ticket_system_log"

int fifo_server_run();
int socket_server_run();
void sig_chld(int signo);
FILE* open_log_file();

int main()
{
	#ifdef __FIFO_MODE__
	if(fifo_server_run() == -1)
	{
		fprintf(stderr, "fifo server has error\n");
		return -1;
	}
	#elif defined __SOCKET_MODE__
	if(socket_server_run() == -1)
	{
		fprintf(stderr, "socket server has error\n");
		return -1;
	}
	#endif

	return 0;
}

int fifo_server_run()
{
	FILE* read_file;
	if(create_listening_fifo(SERVER_PUBLIC_FIFO_NAME, &read_file) == -1)
	{
		fprintf(stderr, "can't create listening fifo\n");
		return -1;
	}
	
	FILE* log_file;
	log_file = open_log_file();

	bool main_server_has_error = false;

	#ifdef __DEBUG__
	fprintf(stdout, "start listening\n");
	#endif

	// listening to client establish connection request 
	char content[BUFFER_SIZE];
	char* fgets_result;
	pid_t client_pid;
	
	if(signal(SIGCHLD, sig_chld) == SIG_ERR)
	{
		fprintf(stderr, "can't bind signal handler\n");
		main_server_has_error = true;
	}

	while(main_server_has_error == false)
	{
		fgets_result = Fgets(content, sizeof(content), read_file);
		if(fgets_result == NULL)
		{
			fprintf(stderr, "error happens when listening connection\n");
			main_server_has_error = true;
			break;
		}
		else
		{
			if(atoi(content) != ESTABLISH_CONNECTION_REQUEST)
			{
				fprintf(stderr, "expect a ESTABLISH_CONNECTION_REQUEST but get %s\n", content);
				main_server_has_error = true;
				break;
			}
			if(read_line(content, sizeof(content), read_file, false) == NULL)
			{
				fprintf(stderr, "can't get client pid\n");
				main_server_has_error = true;
				break;
			}
			client_pid = atoi(content);

			if(fork() == 0) // child process
			{
				int child_server_status = 0;

				if(close_listening_fifo(read_file) == -1)
				{
					fprintf(stderr, "server child close listening fifo error\n");
					return -1;
				}

				FILE* write_file;
				if(establish_client_server_fifo_connection(client_pid, &read_file, &write_file) == -1)				
				{
					fprintf(stderr, "can't establish client server fifo connection\n");
					return -1;
				}
				#ifdef __DEBUG__
				fprintf(stdout, "establish client server fifo connection\n");
				#endif
				
				if(run_server_core(read_file, write_file, log_file) == -1)
				{
					fprintf(stderr, "server core has error\n");
					child_server_status = -1;
				}
				
				// disconnect client and close resources
				if(fclose(write_file) == EOF)
				{
					fprintf(stderr, "close the write file occurs an error\n");
					child_server_status = -1;
				}
				if(fclose(read_file) == EOF)
				{
					fprintf(stderr, "close the read file occurs an error\n");
					child_server_status = -1;
				}
				if(log_file != NULL)
				{
					fclose(log_file);
				}
				return child_server_status;
			}
		}
	}
	
	// you go here means you have something wrong
	if(close_listening_fifo(read_file) == -1)
	{
		fprintf(stderr, "server child close listening fifo error\n");
	}
	if(log_file != NULL)
	{
		fclose(log_file);
	}

	return -1;
}

int socket_server_run()
{
	int listen_fd, connect_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len;

	if((listen_fd = create_listening_socket()) == -1)
	{
		fprintf(stderr, "can't create listening socket\n");
		return -1;
	}
	
	FILE* log_file;
	log_file = open_log_file();

	bool main_server_has_error = false;

	#ifdef __DEBUG__
	fprintf(stdout, "start listening\n");
	#endif

	if(signal(SIGCHLD, sig_chld) == SIG_ERR)
	{
		fprintf(stderr, "can't bind signal handler\n");
		main_server_has_error = true;
	}
	
	while(main_server_has_error == false)
	{
		client_len = sizeof(client_addr);
		if((connect_fd = Accept(listen_fd, (SA*)&client_addr, &client_len)) == -1)
		{
			fprintf(stderr, "accept error\n");
			main_server_has_error = true;
			break;
		}

		if(fork() == 0) // child process
		{
			int child_server_status = 0;

			FILE* read_file;
			FILE* write_file;

			if(close(listen_fd) == -1)
			{
				fprintf(stderr, "server child close listening socket error\n");
				child_server_status = -1;
			}
			
			if((read_file = fdopen(connect_fd, "r+")) == NULL)
			{
				fprintf(stderr, "convertion from connected socket fd to FILE struct has error\n");
				close(connect_fd);
				child_server_status = -1;
			}
			else
			{
				write_file = read_file; // socket is duplex

				#ifdef __DEBUG__
				fprintf(stdout, "establish client server socket connection\n");
				#endif

				if(run_server_core(read_file, write_file, open_log_file()) == -1)
				{
					fprintf(stderr, "server core has error\n");
					child_server_status = -1;
				}

				//disconnect client socket is duplex, so read_file and write_file is the same file
				if(fclose(read_file) == EOF)
				{
					fprintf(stderr, "close the read file occurs an error\n");
					child_server_status = -1;
				}

				if(log_file != NULL)
				{
					fclose(log_file);
				}
			}
			
			return child_server_status;
		}

		if(close(connect_fd) == -1)
		{
			fprintf(stderr, "server close connected socket error\n");
			return -1;
		}
	}

	// you go here means you have something wrong
	if(close(listen_fd) == -1)
	{
		fprintf(stderr, "server child close listening socket error\n");
	}
	if(log_file != NULL)
	{
		fclose(log_file);
	}

	return -1;
}

void sig_chld(int signo)
{
	pid_t pid;
	int stat;
	
	while((pid = waitpid(-1, &stat, WNOHANG)) > 0)
	{
		#ifdef __DEBUG__
		printf("child %d terminated\n", pid);
		#endif
	}
	
	return;
}

FILE* open_log_file()
{
	FILE* log_file;
	if((log_file = fopen(SYSTEM_LOG, "a")) == NULL)
	{
		fprintf(stderr, "can't open log file: %s\n", strerror(errno));
	}
	
	return log_file;
}
