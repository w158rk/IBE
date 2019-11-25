#include<thread>

#include "comm_lcl.hpp"

#ifdef DEBUG 
#include<iostream>
#endif

using namespace comm;

void Comm::socket_main()
{
	std::thread *listener = new std::thread(&Comm::socket_listener_run, std::ref(*this));
	user_set_thread(this, listener);				// maintain a pointer 
	// listener->detach();
}



void Comm::file_main(user::User *user, 
					std::FILE *read_file, 
					std::FILE *write_file) 
{
	Comm* comm = new Comm;
	// set the files
	comm->set_read_file(read_file);
	comm->set_write_file(write_file);
	// add the comm in the user's set 
	// this must be run before the thread runs
	user_add_client(comm, user);
	// get the listening thread run
	std::thread *listener = new std::thread(&Comm::file_listener_run, comm);
	// add the listener as the member of comm
	comm->set_thread(listener);
	// add the thread to the thread pool 
	user_add_thread(user, listener);
	// listener->join();
	
}
