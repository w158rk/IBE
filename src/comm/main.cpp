#include<thread>
#include<comm.hpp>

#ifdef DEBUG 
#include<iostream>
#endif

using namespace comm;

void Comm::socket_main()
{
	std::thread *listener = new std::thread(&Comm::socket_listener_run, std::ref(*this));
	get_user_ptr()->set_thread(listener);				// maintain a pointer 
	// listener->detach();
}



void interface::IComm::file_main(interface::IUser *user, 
					std::FILE *read_file, 
					std::FILE *write_file) 
{
	Comm* comm = new Comm;
	// set the files
	comm->set_read_file(read_file);
	comm->set_write_file(write_file);
	// add the comm in the user's set 
	// this must be run before the thread runs
	user->add_client(comm);
	// get the listening thread run
	std::thread *listener = new std::thread(&Comm::file_listener_run, comm);
	// add the listener as the member of comm
	comm->set_thread(listener);
	// add the thread to the thread pool 
	user->add_thread(listener);
	// listener->join();
	
}
