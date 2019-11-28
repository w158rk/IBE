#include "user_lcl.hpp"
#include <comm.hpp>

using namespace user;
using namespace comm;

void user::comm_file_main(user::User *user, 
					std::FILE *read_file, 
					std::FILE *write_file)
{
    Comm::file_main(user, read_file, write_file);
}

Comm *user::comm_new()
{
    return new Comm;
}

void user::comm_delete(Comm *comm)
{
	delete comm;
}

void comm_connect_to_server(comm::Comm *comm, char*server_ip, int server_port)
{
	return comm->connect_to_server(server_ip, server_port);
}
