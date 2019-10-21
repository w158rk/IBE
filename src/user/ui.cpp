#include<ui.hpp>
#include<user.hpp>
#include<config.h>
#include<string.h>

using namespace ui;

UInterface::UInterface() {
	int i=0;
}

void UInterface::run() {
	socket_interface_run();
}

int UInterface::socket_interface_run() {

	interface::IUser *user = get_user_ptr();
    ID *user_id = user->get_id();
	
	printf("What do you want to do? %s\n", user_id->id);
	printf("Choose from :\n");
	printf("\t1. Extract your Private Key\n");
	printf("\t2. Send message\n");
	
	int choise;
	scanf("%d", &choise);
	switch (choise) {
		case 1/* constant-expression */:
		{	/* code */
			user::Client *client = dynamic_cast<user::Client *>(user);
			if (-1 == client->run_get_private_key(SERVER_IP_ADDRESS, SERVER_LISTEN_PORT)) {
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
			if(-1 == user->run_send_message(ip_ad, port, &dest_id))
			{
				return -1;
			}
			break;
		}
		default:
			break;
	}

	return 0;
}