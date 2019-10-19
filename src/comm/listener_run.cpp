#include <comm.hpp>

extern "C" {

#include <stdio.h>
#include "depend.h"
#include "comm_lcl.h"

}


void comm::Comm::file_listener_run()
{
	if(!m_ferr_sig | !m_fread_file | !m_fwrite_file){
        fprintf(stderr, "[error] flags are not set completely, check the error sig and files\n", __FILE__, __LINE__);
		return ;
    }

	bool main_server_has_error = false;

	if(signal(SIGCHLD, sig_chld) == SIG_ERR)					// 锁
	{
		fprintf(stderr, "can't bind signal handler\n");
		main_server_has_error = true;
	}

	if(signal(SIGCHLD, sig_chld) == SIG_ERR)					// 锁
	{
		fprintf(stderr, "can't bind signal handler\n");
		main_server_has_error = true;
	}

	if(fork() == 0) // child process
	{				// 监听进程
		int child_server_status = 0;

		/*处理监听事件*/
		if(run_listen_core() == -1)
		{
			// 业务
			fprintf(stderr, "server core has error\n");
			child_server_status = -1;
		}

		//disconnect client socket is duplex, so read_file and write_file is the same file
		if(fclose(m_read_file) == EOF)
		{
			fprintf(stderr, "close the read file occurs an error\n");
			child_server_status = -1;
		}
		m_fread_file = false;
		m_fwrite_file = false;

	}

	*m_err_sig = -1;
}

void comm::Comm::socket_listener_run()
{
	if(!m_ferr_sig | m_fread_file | m_fwrite_file){
        fprintf(stderr, "[error] flags are not set completely, check the error sig and files\n", __FILE__, __LINE__);
		return ;
    }

	int listen_fd, connect_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len;

	// create the socket 
	int listen_port = get_user_ptr()->get_port();
	if((listen_fd = create_listening_socket(listen_port)) == -1)
	{
		fprintf(stderr, "can't create listening socket\n");
		*m_err_sig = -1;
	}
	

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
				m_write_file = write_file;
				m_read_file = read_file;
				m_fwrite_file = true;
				m_fread_file = true;

				#ifdef __DEBUG__
				fprintf(stdout, "establish client server socket connection\n");
				#endif

				/*处理监听事件*/
				if(run_listen_core() == -1)
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
				
				m_fread_file = false;
				m_fwrite_file = false;

			}
			
		}

		if(close(connect_fd) == -1)
		{
			fprintf(stderr, "server close connected socket error\n");
			*m_err_sig = -1;
		}
	}

	// you go here means you have something wrong
	if(close(listen_fd) == -1)
	{
		fprintf(stderr, "server child close listening socket error\n");
	}

	*m_err_sig = -1;
}

