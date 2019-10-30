#include<user.hpp>
#include<packet.hpp>

using namespace user;

void User::delete_thread(std::thread *thread)
{

    if(thread==nullptr)
    {
        throw UserException("The thread used by add_client is null");
    }

    client_threads.erase(thread);
    delete thread;


}