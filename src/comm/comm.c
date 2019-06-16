#include <pthread.h>
#include "base.h"
#include "comm.h"

int socket_main(const char* entity_id, int id_len, int port) {
	// 启动一个监听线程
	char error_sig = 0;
	pthread_t threads[NUM_THREADS];

	// 函数参数
	char args[MAX_ID_SIZE+8];			// 对齐
	args[0] = error_sig;

    int *p = (int *)args + 1;
    *p = port;

	memcpy(args+8, entity_id, MAX_ID_SIZE);
	
	int listen_rc = pthread_create(&threads[0], NULL, socket_listener_run, (void *)args);
	if(listen_rc) {
		fprintf(stderr, "create listening thread fail\n");
		return -1;
	}

	while (-1 != args[0]) {
		if(-1 == socket_interface_run(entity_id, id_len)) {
			args[0] = -1;
		}
	}
}