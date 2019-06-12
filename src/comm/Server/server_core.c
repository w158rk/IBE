#include "../client_server.h"
#include "../../crypto/crypto.h"

char sk_filename[] = "server_sk.conf";

static FILE* read_file;
static FILE* write_file;
static FILE* log_file;
static char content[BUFFER_SIZE];
static long int current_client_id;

int handle_finish_request();
int handle_login_request();
int handle_order_request();
int handle_refund_request();
int handle_register_request();
int handle_query_booked_ticket_request();
int handle_query_by_station_request();

int run_server_core(FILE* read, FILE* write, FILE* log)
{
	// init the static variable
	read_file = read;
	write_file = write;
	log_file = log;
	current_client_id = -1;

	char crypto_type;
	do
	{	
		errno = 0; // clear the errno
		// if(read_line(content, sizeof(content), read_file, false) == NULL)
		if(fread(&crypto_type, sizeof(crypto_type), 1, read_file) == NULL)
		{
			if(feof(read_file))
			{
				fprintf(stdout, "client close its connection abruptly\n");
				return 0;
			}
			else
			{
				fprintf(stderr, "can't get user request: %s\n", strerror(errno));
				return -1;
			}
		}
		switch (crypto_type)
		{
			case CRYPTO_IBE:
				if(handle_ibe() == -1)
				{
					fprintf(stderr, "handle IBE packet error\n");
					return -1;
				}
				break;
			case CRYPTO_AES:
				if(handle_aes() == -1)
				{
					fprintf(stderr, "handle AES packet error\n");
					return -1;
				}
				break;
		}
	} while(1);				// 客户端关闭之前一直执行

	return 0;
}

