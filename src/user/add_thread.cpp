#include<user.hpp>
#include<packet.hpp>
#include<thread>

using namespace user;

void User::add_thread(std::thread *thread)
{

    if(thread==nullptr)
    {
        throw UserException("The thread used by add_thread is null");
    }

    // add the comm into the comm set for the current linked client 
    client_threads.insert(thread);

}