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