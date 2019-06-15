#include "client_server.h"
#include "../crypto/crypto.h"

char sk_filename[] = "server_sk.conf";

static long int current_client_id;

int run_server_core(const char* server_id, FILE* read_file, FILE* write_file, FILE* log_file)
{
	// init the static variable
	current_client_id = -1;

	char crypto_type;
	do
	{	
		errno = 0; // clear the errno
		if(!fread(&crypto_type, sizeof(crypto_type), 1, read_file))
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
				if(handle_ibe(server_id, read_file, write_file) == -1)
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

