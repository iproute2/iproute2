#if HAVE_SELINUX
#include <selinux/selinux.h>
#else
int is_selinux_enabled(void);
void freecon(char *context);
int getpidcon(pid_t pid, char **context);
int getfilecon(const char *path, char **context);
int security_get_initial_context(const char *name,  char **context);
int setexecfilecon(const char *filename, const char *fallback_type);
#endif
