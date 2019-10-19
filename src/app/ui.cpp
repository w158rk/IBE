#include<ui.hpp>

extern "C" {
    #include <func.h>
}

using namespace ui;

UInterface::UInterface() {

}

int UInterface::socket_interface_run() {

    ID *untity_id = get_user_ptr()->get_id();
	
	printf("What do you want to do? %s\n", untity_id->id);
	printf("Choose from :\n");
	printf("\t1. Extract your Private Key\n");
	printf("\t2. Send message\n");
	
	int choise;
	scanf("%d", &choise);
	switch (choise) {
		case 1/* constant-expression */:
			/* code */
			if (-1 == run_get_private_key(untity_id->id, untity_id->length, untity_id->father_node)) {
				return -1;
			}			
			break;
		case 2:
		{
			printf("Please input whom you want to send to(IP_ADDRESS LISTEN_PORT ID)\n");
			char ip_ad[20], dest_id[20];
			int port;
			scanf("%s %d %s",&ip_ad, &port, &dest_id);
			fprintf(stderr, "ip is: %s  port is: %d  id is: %s\n", ip_ad, port, dest_id);
			if(-1 == run_send_message(untity_id->id, untity_id->length, ip_ad, port, dest_id))
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