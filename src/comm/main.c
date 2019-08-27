#include <pthread.h>
#include "base.h"
#include "comm.h"

int socket_interface_run(const char* entity_id, int id_len) {
	
	printf("What do you want to do? %s\n", entity_id);
	printf("Choose from :\n");
	printf("\t1. Extract your Private Key\n");
	
	int choise;
	scanf("%d", &choise);
	switch (choise) {
		case 1/* constant-expression */:
			/* code */
			if (-1 == run_get_private_key(entity_id, id_len)) {
				return -1;
			}			
			break;
		default:
			break;
	}

	return 0;
}

void *socket_listener_run(void *args)
{
	char *error_sig = (char *)args;

	int *entity_id_len = *(int *)(args+8);
	char *entity_id = (char *)malloc(entity_id_len);
	memcpy(entity_id, (char *)args+12, entity_id_len);

	int listen_fd, connect_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len;

	int *p = (int *)(args+4);			// 读取监听端口
	int listen_port = *p;

	if((listen_fd = create_listening_socket(listen_port)) == -1)
	{
		fprintf(stderr, "can't create listening socket\n");
		*error_sig = -1;
	}
	
	FILE* log_file;
	log_file = open_log_file();

	bool main_server_has_error = false;

	#ifdef __DEBUG__
	fprintf(stdout, "start listening\n");
	#endif

	if(signal(SIGCHLD, sig_chld) == SIG_ERR)					// 锁
	{
		fprintf(stderr, "can't bind signal handler\n");
		main_server_has_error = true;
	}
	
	while(main_server_has_error == false)					// 业务
	{
		client_len = sizeof(client_addr);
		if((connect_fd = Accept(listen_fd, (SA*)&client_addr, &client_len)) == -1)				// 建立连接
		{
			fprintf(stderr, "accept error\n");
			main_server_has_error = true;
			break;
		}

		if(fork() == 0) // child process
		{				// 监听进程
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

				if(run_listen_core(entity_id, entity_id_len, read_file, write_file, open_log_file()) == -1)
				{
					// 业务
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
			
			// return child_server_status;
		}

		if(close(connect_fd) == -1)
		{
			fprintf(stderr, "server close connected socket error\n");
			*error_sig = -1;
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

	free(entity_id);
	*error_sig = -1;
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


int socket_main(const char* entity_id, int id_len, int port) {
	// 启动一个监听线程
	char error_sig = 0;
	pthread_t threads[NUM_THREADS];

	// 函数参数
	char *args = (char *)malloc(12 + id_len);
	*(int *)args = error_sig;
	*(int *)(args+4) = port;
	*(int *)(args+8) = id_len;

	memcpy(args+12, entity_id, id_len);
	
	int listen_rc = pthread_create(&threads[0], NULL, socket_listener_run, (void *)args);
	if(listen_rc) {
		fprintf(stderr, "create listening thread fail\n");
		return -1;
	}
        
        // user interface
	while (-1 != args[0]) {
		if(-1 == socket_interface_run(entity_id, id_len)) {
			args[0] = -1;
		}
	}
}
