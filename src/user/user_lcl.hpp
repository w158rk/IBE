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

}

#endif