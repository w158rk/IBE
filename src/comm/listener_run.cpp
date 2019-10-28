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
	
	// do not use the child process, use the thread directly
	/*处理监听事件*/
	if(run_listen_core() == -1)
	{
		// 业务
		fprintf(stderr, "server core has error\n");
		goto end;
	}

	//disconnect client socket is duplex, so read_file and write_file is the same file
	if(fclose(m_read_file) == EOF)
	{
		fprintf(stderr, "close the read file occurs an error\n");
		goto end;
	}

end:
	*m_err_sig = -1;
	m_fread_file = false;
	m_fwrite_file = false;

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

	while(main_server_has_error == false)					// 业务
	{
		client_len = sizeof(client_addr);
		if((connect_fd = Accept(listen_fd, (SA*)&client_addr, &client_len)) == -1)				// 建立连接
		{
			fprintf(stderr, "accept error\n");
			main_server_has_error = true;
			break;
		}

		FILE* read_file;

		if((read_file = fdopen(connect_fd, "r+")) == NULL)
		{
			fprintf(stderr, "convertion from connected socket fd to FILE struct has error\n");
			close(connect_fd);
			main_server_has_error = -1;
		}
		else
		{
			set_write_file(read_file);
			set_read_file(read_file);

#ifdef DEBUG
			fprintf(stdout, "establish client server socket connection\n");
#endif

		/*处理监听事件*/
		if(run_listen_core() == -1)
		{
			// 业务
			fprintf(stderr, "server core has error\n");
			main_server_has_error = -1;
		}

		//disconnect client socket is duplex, so read_file and write_file is the same file
		if(fclose(read_file) == EOF)
		{
			fprintf(stderr, "close the read file occurs an error\n");
			main_server_has_error = -1;
		}

		m_read_file = nullptr;	
		m_write_file = nullptr;	
		m_fread_file = false;
		m_fwrite_file = false;

		}


		if(fork() == 0) // child process
		{				// 监听进程
			int child_server_status = 0;


			if(close(listen_fd) == -1)
			{
				fprintf(stderr, "server child close listening socket error\n");
				child_server_status = -1;
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

