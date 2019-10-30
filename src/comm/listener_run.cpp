#include <comm.hpp>

extern "C" {

#include <stdio.h>
#include "depend.h"
#include "comm_lcl.h"

}

#include<iostream>

void comm::Comm::file_listener_run()
{
	if(!m_fread_file | !m_fwrite_file){
        fprintf(stderr, "[error] flags are not set completely, check the error sig and files\n", __FILE__, __LINE__);
		return ;
    }
	
	// do not use the child process, use the thread directly
	if(run_listen_core() == -1)
	{
		// 业务
		fprintf(stderr, "server core has error\n");
	}

	//if you get here, that means the listener has something wrong
	//disconnect client socket is duplex, so read_file and write_file is the same file
	if(fclose(m_read_file) == EOF)
	{
		fprintf(stderr, "close the read file occurs an error\n");
	}

#ifdef DEBUG 
	fprintf(stderr, "end handling the packet\n");
#endif

	// handle finished
	// delete this comm and the thread
	get_user_ptr()->delete_client(this);
	// get_user_ptr()->delete_thread(get_thread());
#ifdef DEBUG 
	fprintf(stderr, "remove the listening comm from the user\n");
#endif
	while(true);		// keep it running, because segmentation fault happends when terminiating

}

void comm::Comm::socket_listener_run()
{
	if(m_fread_file | m_fwrite_file){
#ifdef DEBUG 
		std::cerr << "m_fread_file: " << m_fread_file << std::endl;
		std::cerr << "m_fwrite_file: " << m_fwrite_file << std::endl;
#endif
		throw comm::CommException("[error in socket_listener_run] flags are not set properly, check the files");
    }

	int listen_fd, connect_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len;

	// create the socket 
	int listen_port = get_user_ptr()->get_port();
	if((listen_fd = create_listening_socket(listen_port)) == -1)
	{
		fprintf(stderr, "can't create listening socket\n");
	}
	

	bool main_server_has_error = false;

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
			// if accept a new client, generate a new listening thread for that client 
			interface::IComm::file_main(get_user_ptr(), read_file, read_file);

		}
#ifdef DEBUG 
	fprintf(stderr, "================finish a round of the loop==================\n");
#endif

	}

#ifdef DEBUG 
	fprintf(stderr, "try to close the listen_fd\n");
#endif
	// you go here means you have something wrong
	if(close(listen_fd) == -1)
	{
		fprintf(stderr, "server child close listening socket error\n");
	}

#ifdef DEBUG 
	fprintf(stderr, "end closing the listen_fd\n");
#endif

}

