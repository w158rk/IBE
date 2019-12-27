#ifndef USER_LCL_HPP 
#define COMM_LCL_HPP 

#include <user.hpp>

/**
 * interface functions 
 */
namespace user
{

    void comm_file_main(user::User *user, 
					std::FILE *read_file, 
					std::FILE *write_file);
	comm::Comm *comm_new();
	void comm_delete(comm::Comm *);
	void comm_connect_to_server(comm::Comm *, char*server_ip, int server_port);
	void comm_socket_listener_run(interface::IComm *comm);

}

#endif