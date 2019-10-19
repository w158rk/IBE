#include<thread>
#include<comm.hpp>

using namespace comm;

void Comm::socket_main()
{
	std::thread listener(&Comm::socket_listener_run, this);
	listener.detach();
}



void Comm::file_main() {

	std::thread listener(&Comm::file_listener_run, this);
	listener.detach();
	
}
