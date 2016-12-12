#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "utils.h"

int cmd_exec(const char *cmd, char **argv, bool do_fork)
{
	fflush(stdout);
	if (do_fork) {
		int status;
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			perror("fork");
			exit(1);
		}

		if (pid != 0) {
			/* Parent  */
			if (waitpid(pid, &status, 0) < 0) {
				perror("waitpid");
				exit(1);
			}

			if (WIFEXITED(status)) {
				return WEXITSTATUS(status);
			}

			exit(1);
		}
	}

	if (execvp(cmd, argv)  < 0)
		fprintf(stderr, "exec of \"%s\" failed: %s\n",
				cmd, strerror(errno));
	_exit(1);
}
