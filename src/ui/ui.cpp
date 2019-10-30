#include<ui.hpp>
#include<user.hpp>
#include<config.h>
#include<string.h>

#include <iostream>
#include <iomanip>

using namespace ui;

void UInterface::run() {
	socket_interface_run();
}

int UInterface::socket_interface_run() {

	interface::IUser *user = get_user_ptr();
    ID *user_id = user->get_id();
	
	while(true)
	{
		printf("What do you want to do? %s\n", user_id->id);
		printf("Choose from :\n");
		printf("\t1. Extract your Private Key\n");
		printf("\t2. Send message\n");
		
		int choise;
		scanf("%d", &choise);

		// get the ip and listen port of server 

		ID *id = get_user_ptr()->get_id();
		ID *parent = id->father_node;

		switch (choise) {
			case 1:
			{	
				user::User *client = dynamic_cast<user::User *>(user);
				try 
				{
					client->run_get_private_key(parent->ip, parent->port);
				}			
				catch(user::UserException& e)
				{
					std::cerr << e.what() << std::endl;
					return -1;
				}
				break;
			}
			case 2:
			{
				printf("Please input whom you want to send to(IP_ADDRESS LISTEN_PORT ID)\n");
				char ip_ad[20], id_cstr[20];
				int port;
				scanf("%s %d %s",&ip_ad, &port, &id_cstr);
				ID dest_id;
				dest_id.id = id_cstr;
				int len = strlen(id_cstr);
				dest_id.length = len;
				fprintf(stderr, "ip is: %s  port is: %d  id is: %s\n", ip_ad, port, id_cstr);
				try 
				{
					user->run_send_message(ip_ad, port, &dest_id);
				}
				catch(user::UserException& e)
				{
					std::cerr << e.what() << std::endl;
					return -1;
				}			
				break;
			}
			default:
				break;
		}

	}

	return 0;
}

void UInterface::print(char *message, int length) 
{
	std::string out(message, length);
	std::cout << "[info]" << out << std::endl;
}


void UInterface::print(std::string message) 
{
	
}

void UInterface::error(char *message, int length) 
{

}

void UInterface::error(std::string message) 
{
	
}
