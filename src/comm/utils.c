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

