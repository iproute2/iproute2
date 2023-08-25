#include <stdlib.h>
#include <unistd.h>
#include "selinux.h"

/* Stubs for SELinux functions */
int is_selinux_enabled(void)
{
	return 0;
}

void freecon(char *context)
{
	free(context);
}

int getpidcon(pid_t pid, char **context)
{
	*context = NULL;
	return -1;
}

int getfilecon(const char *path, char **context)
{
	*context = NULL;
	return -1;
}

int security_get_initial_context(const char *name,  char **context)
{
	*context = NULL;
	return -1;
}

int setexecfilecon(const char *filename, const char *fallback_type)
{
	return -1;
}
