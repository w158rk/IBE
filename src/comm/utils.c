#include "depend.h"
#include "comm.h"
#include <config.h>

void sig_chld(int signo)
{
	pid_t pid;
	int stat;
	
	while((pid = waitpid(-1, &stat, WNOHANG)) > 0)
	{
		#ifdef __DEBUG__
		printf("child %d terminated\n", pid);
		#endif
	}
	
	return;
}

FILE* open_log_file()
{
	FILE* log_file;
	if((log_file = fopen(SYSTEM_LOG, "a")) == NULL)
	{
		fprintf(stderr, "can't open log file: %s\n", strerror(errno));
	}
	
	return log_file;
}


