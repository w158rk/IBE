#include<ui.hpp>
#include<user.hpp>
#include<config.h>
#include<string.h>
#include <time.h>

#include <iostream>

#define RESET "\033[0m"
#define BLACK "\033[30m" 
#define RED "\033[31m" 
#define GREEN "\033[32m" 
#define YELLOW "\033[33m" 
#define BLUE "\033[34m" 
#define MAGENTA "\033[35m" 
#define CYAN "\033[36m" 
#define WHITE "\033[37m" 
#define BOLDBLACK "\033[1m\033[30m" 
#define BOLDRED "\033[1m\033[31m" 
#define BOLDGREEN "\033[1m\033[32m" 
#define BOLDYELLOW "\033[1m\033[33m" 
#define BOLDBLUE "\033[1m\033[34m" 
#define BOLDMAGENTA "\033[1m\033[35m" 
#define BOLDCYAN "\033[1m\033[36m" 
#define BOLDWHITE "\033[1m\033[37m" 

using namespace ui;
using namespace interface;

void UInterface::run() {
	socket_interface_run();
}

int UInterface::socket_interface_run() 
{

	user::User *usr = get_user_ptr();
    ID *user_id = usr->get_id();
	
	while(true)
	{
		user::User *user = reinterpret_cast<user::User *>(usr);
		printf("What do you want to do? %s\n", user_id->id);
		printf("Choose from :\n");
		printf("\t1. Extract your Private Key\n");
		printf("\t2. Send message\n");
		printf("\t3. Try to send message cross-domain\n");
		printf("\t4. Set up your system\n");
		printf("\t5. Read your system files\n");
		printf("\t6. Init the whole system\n");
		printf("\t7. Get global and domain mpk\n");
		printf("\t8. Get the gateway and internet session keys\n");
		printf("\t9. Get the IOT session keys\n");
		
		int choise;
		scanf("%d", &choise);

		// get the ip and listen port of server 

		ID *id = get_user_ptr()->get_id();
		ID *parent = id->father_node;

		switch (choise) {
			case 1:
			{	
				try 
				{
					user->run_get_private_key(parent->ip, parent->port);
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
			case 3:
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
					user->try_send_message(ip_ad, port, &dest_id);
				}
				catch(user::UserException& e)
				{
					std::cerr << e.what() << std::endl;
					return -1;
				}			
				break;
			}
			case 4:
			{
				double start,end,cost;
        		start=clock();
				user->sys_setup();
				end=clock();
        		cost=(end-start)/CLOCKS_PER_SEC*1000;
        		printf("sys setup time is: %f ms\n",cost);
				break;
			}
			case 5:
			{
				user->sys_read();
				break;
			}
			case 6:
			{
				double start,end,cost;
        		start=clock();
				user->sys_init();
				end=clock();
        		cost=(end-start)/CLOCKS_PER_SEC*1000;
        		printf("whole init time is: %f ms\n",cost);
				break;
			}
			case 7:
			{
				try 
				{
					user->run_get_mpk(parent->ip, parent->port);
				}			
				catch(user::UserException& e)
				{
					std::cerr << e.what() << std::endl;
					return -1;
				}
				break;
			}
			case 8:
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
					user->run_get_Intkey(ip_ad, port, &dest_id);
				}
				catch(user::UserException& e)
				{
					std::cerr << e.what() << std::endl;
					return -1;
				}			
				break;
			}
			case 9:
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
					user->run_get_IOTkey(ip_ad, port, &dest_id);
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

void IUI::print(char *message, int length) 
{
	std::string out(message, length);
	std::cout << BOLDWHITE << "[info] " << RESET << out << std::endl;
}


void IUI::print(std::string message) 
{
	std::cout << BOLDWHITE << "[info] " << RESET << message << std::endl;
}

void IUI::error(char *message, int length) 
{
	std::string out(message, length);
	std::cerr << BOLDRED << "[error] " << RESET << out << std::endl;
}

void IUI::error(std::string message) 
{
	std::cerr << BOLDRED << "[error] " << RESET << message << std::endl;
}

void IUI::debug(char *message, int length) 
{
	std::string out(message, length);
	std::cerr << BOLDBLUE << "[debug] " << RESET << out << std::endl;
}

void IUI::debug(std::string message) 
{
	std::cerr << BOLDBLUE << "[debug] " << RESET << message << std::endl;
}


GET_AND_SET_IMPL(UInterface, user::User * , user_ptr)
