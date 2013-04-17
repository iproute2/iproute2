#define _ATFILE_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include "utils.h"
#include "ip_common.h"

#define NETNS_RUN_DIR "/var/run/netns"
#define NETNS_ETC_DIR "/etc/netns"

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
#endif

#ifndef MNT_DETACH
#define MNT_DETACH	0x00000002	/* Just detach from the tree */
#endif /* MNT_DETACH */

/* sys/mount.h may be out too old to have these */
#ifndef MS_REC
#define MS_REC		16384
#endif

#ifndef MS_SLAVE
#define MS_SLAVE	(1 << 19)
#endif

#ifndef MS_SHARED
#define MS_SHARED	(1 << 20)
#endif


#ifndef HAVE_SETNS
static int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif /* HAVE_SETNS */

static int usage(void)
{
	fprintf(stderr, "Usage: ip netns list\n");
	fprintf(stderr, "       ip netns add NAME\n");
	fprintf(stderr, "       ip netns delete NAME\n");
	fprintf(stderr, "       ip netns identify PID\n");
	fprintf(stderr, "       ip netns pids NAME\n");
	fprintf(stderr, "       ip netns exec NAME cmd ...\n");
	fprintf(stderr, "       ip netns monitor\n");
	return EXIT_FAILURE;
}

int get_netns_fd(const char *name)
{
	char pathbuf[MAXPATHLEN];
	const char *path, *ptr;

	path = name;
	ptr = strchr(name, '/');
	if (!ptr) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
			NETNS_RUN_DIR, name );
		path = pathbuf;
	}
	return open(path, O_RDONLY);
}

static int netns_list(int argc, char **argv)
{
	struct dirent *entry;
	DIR *dir;

	dir = opendir(NETNS_RUN_DIR);
	if (!dir)
		return EXIT_SUCCESS;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;
		printf("%s\n", entry->d_name);
	}
	closedir(dir);
	return EXIT_SUCCESS;
}

static void bind_etc(const char *name)
{
	char etc_netns_path[MAXPATHLEN];
	char netns_name[MAXPATHLEN];
	char etc_name[MAXPATHLEN];
	struct dirent *entry;
	DIR *dir;

	snprintf(etc_netns_path, sizeof(etc_netns_path), "%s/%s", NETNS_ETC_DIR, name);
	dir = opendir(etc_netns_path);
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;
		snprintf(netns_name, sizeof(netns_name), "%s/%s", etc_netns_path, entry->d_name);
		snprintf(etc_name, sizeof(etc_name), "/etc/%s", entry->d_name);
		if (mount(netns_name, etc_name, "none", MS_BIND, NULL) < 0) {
			fprintf(stderr, "Bind %s -> %s failed: %s\n",
				netns_name, etc_name, strerror(errno));
		}
	}
	closedir(dir);
}

static int netns_exec(int argc, char **argv)
{
	/* Setup the proper environment for apps that are not netns
	 * aware, and execute a program in that environment.
	 */
	const char *name, *cmd;
	char net_path[MAXPATHLEN];
	int netns;

	if (argc < 1) {
		fprintf(stderr, "No netns name specified\n");
		return EXIT_FAILURE;
	}
	if (argc < 2) {
		fprintf(stderr, "No command specified\n");
		return EXIT_FAILURE;
	}
	name = argv[0];
	cmd = argv[1];
	snprintf(net_path, sizeof(net_path), "%s/%s", NETNS_RUN_DIR, name);
	netns = open(net_path, O_RDONLY);
	if (netns < 0) {
		fprintf(stderr, "Cannot open network namespace \"%s\": %s\n",
			name, strerror(errno));
		return EXIT_FAILURE;
	}
	if (setns(netns, CLONE_NEWNET) < 0) {
		fprintf(stderr, "seting the network namespace \"%s\" failed: %s\n",
			name, strerror(errno));
		return EXIT_FAILURE;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		fprintf(stderr, "unshare failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	/* Don't let any mounts propogate back to the parent */
	if (mount("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
		fprintf(stderr, "\"mount --make-rslave /\" failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	/* Mount a version of /sys that describes the network namespace */
	if (umount2("/sys", MNT_DETACH) < 0) {
		fprintf(stderr, "umount of /sys failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	if (mount(name, "/sys", "sysfs", 0, NULL) < 0) {
		fprintf(stderr, "mount of /sys failed: %s\n",strerror(errno));
		return EXIT_FAILURE;
	}

	/* Setup bind mounts for config files in /etc */
	bind_etc(name);

	if (execvp(cmd, argv + 1)  < 0)
		fprintf(stderr, "exec of \"%s\" failed: %s\n",
			cmd, strerror(errno));
	return EXIT_FAILURE;
}

static int is_pid(const char *str)
{
	int ch;
	for (; (ch = *str); str++) {
		if (!isdigit(ch))
			return 0;
	}
	return 1;
}

static int netns_pids(int argc, char **argv)
{
	const char *name;
	char net_path[MAXPATHLEN];
	int netns;
	struct stat netst;
	DIR *dir;
	struct dirent *entry;

	if (argc < 1) {
		fprintf(stderr, "No netns name specified\n");
		return EXIT_FAILURE;
	}
	if (argc > 1) {
		fprintf(stderr, "extra arguments specified\n");
		return EXIT_FAILURE;
	}

	name = argv[0];
	snprintf(net_path, sizeof(net_path), "%s/%s", NETNS_RUN_DIR, name);
	netns = open(net_path, O_RDONLY);
	if (netns < 0) {
		fprintf(stderr, "Cannot open network namespace: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	if (fstat(netns, &netst) < 0) {
		fprintf(stderr, "Stat of netns failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	dir = opendir("/proc/");
	if (!dir) {
		fprintf(stderr, "Open of /proc failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	while((entry = readdir(dir))) {
		char pid_net_path[MAXPATHLEN];
		struct stat st;
		if (!is_pid(entry->d_name))
			continue;
		snprintf(pid_net_path, sizeof(pid_net_path), "/proc/%s/ns/net",
			entry->d_name);
		if (stat(pid_net_path, &st) != 0)
			continue;
		if ((st.st_dev == netst.st_dev) &&
		    (st.st_ino == netst.st_ino)) {
			printf("%s\n", entry->d_name);
		}
	}
	closedir(dir);
	return EXIT_SUCCESS;
	
}

static int netns_identify(int argc, char **argv)
{
	const char *pidstr;
	char net_path[MAXPATHLEN];
	int netns;
	struct stat netst;
	DIR *dir;
	struct dirent *entry;

	if (argc < 1) {
		fprintf(stderr, "No pid specified\n");
		return EXIT_FAILURE;
	}
	if (argc > 1) {
		fprintf(stderr, "extra arguments specified\n");
		return EXIT_FAILURE;
	}
	pidstr = argv[0];

	if (!is_pid(pidstr)) {
		fprintf(stderr, "Specified string '%s' is not a pid\n",
			pidstr);
		return EXIT_FAILURE;
	}

	snprintf(net_path, sizeof(net_path), "/proc/%s/ns/net", pidstr);
	netns = open(net_path, O_RDONLY);
	if (netns < 0) {
		fprintf(stderr, "Cannot open network namespace: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	if (fstat(netns, &netst) < 0) {
		fprintf(stderr, "Stat of netns failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	dir = opendir(NETNS_RUN_DIR);
	if (!dir) {
		/* Succeed treat a missing directory as an empty directory */
		if (errno == ENOENT)
			return EXIT_SUCCESS;

		fprintf(stderr, "Failed to open directory %s:%s\n",
			NETNS_RUN_DIR, strerror(errno));
		return EXIT_FAILURE;
	}

	while((entry = readdir(dir))) {
		char name_path[MAXPATHLEN];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(name_path, sizeof(name_path), "%s/%s",	NETNS_RUN_DIR,
			entry->d_name);

		if (stat(name_path, &st) != 0)
			continue;

		if ((st.st_dev == netst.st_dev) &&
		    (st.st_ino == netst.st_ino)) {
			printf("%s\n", entry->d_name);
		}
	}
	closedir(dir);
	return EXIT_SUCCESS;
	
}

static int netns_delete(int argc, char **argv)
{
	const char *name;
	char netns_path[MAXPATHLEN];

	if (argc < 1) {
		fprintf(stderr, "No netns name specified\n");
		return EXIT_FAILURE;
	}

	name = argv[0];
	snprintf(netns_path, sizeof(netns_path), "%s/%s", NETNS_RUN_DIR, name);
	umount2(netns_path, MNT_DETACH);
	if (unlink(netns_path) < 0) {
		fprintf(stderr, "Cannot remove namespace file \"%s\": %s\n",
			netns_path, strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int netns_add(int argc, char **argv)
{
	/* This function creates a new network namespace and
	 * a new mount namespace and bind them into a well known
	 * location in the filesystem based on the name provided.
	 *
	 * The mount namespace is created so that any necessary
	 * userspace tweaks like remounting /sys, or bind mounting
	 * a new /etc/resolv.conf can be shared between uers.
	 */
	char netns_path[MAXPATHLEN];
	const char *name;
	int fd;
	int made_netns_run_dir_mount = 0;

	if (argc < 1) {
		fprintf(stderr, "No netns name specified\n");
		return EXIT_FAILURE;
	}
	name = argv[0];

	snprintf(netns_path, sizeof(netns_path), "%s/%s", NETNS_RUN_DIR, name);

	/* Create the base netns directory if it doesn't exist */
	mkdir(NETNS_RUN_DIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

	/* Make it possible for network namespace mounts to propogate between
	 * mount namespaces.  This makes it likely that a unmounting a network
	 * namespace file in one namespace will unmount the network namespace
	 * file in all namespaces allowing the network namespace to be freed
	 * sooner.
	 */
	while (mount("", NETNS_RUN_DIR, "none", MS_SHARED | MS_REC, NULL)) {
		/* Fail unless we need to make the mount point */
		if (errno != EINVAL || made_netns_run_dir_mount) {
			fprintf(stderr, "mount --make-shared %s failed: %s\n",
				NETNS_RUN_DIR, strerror(errno));
			return EXIT_FAILURE;
		}

		/* Upgrade NETNS_RUN_DIR to a mount point */
		if (mount(NETNS_RUN_DIR, NETNS_RUN_DIR, "none", MS_BIND, NULL)) {
			fprintf(stderr, "mount --bind %s %s failed: %s\n",
				NETNS_RUN_DIR, NETNS_RUN_DIR, strerror(errno));
			return EXIT_FAILURE;
		}
		made_netns_run_dir_mount = 1;
	}

	/* Create the filesystem state */
	fd = open(netns_path, O_RDONLY|O_CREAT|O_EXCL, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot not create namespace file \"%s\": %s\n",
			netns_path, strerror(errno));
		return EXIT_FAILURE;
	}
	close(fd);
	if (unshare(CLONE_NEWNET) < 0) {
		fprintf(stderr, "Failed to create a new network namespace \"%s\": %s\n",
			name, strerror(errno));
		goto out_delete;
	}

	/* Bind the netns last so I can watch for it */
	if (mount("/proc/self/ns/net", netns_path, "none", MS_BIND, NULL) < 0) {
		fprintf(stderr, "Bind /proc/self/ns/net -> %s failed: %s\n",
			netns_path, strerror(errno));
		goto out_delete;
	}
	return EXIT_SUCCESS;
out_delete:
	netns_delete(argc, argv);
	return EXIT_FAILURE;
}


static int netns_monitor(int argc, char **argv)
{
	char buf[4096];
	struct inotify_event *event;
	int fd;
	fd = inotify_init();
	if (fd < 0) {
		fprintf(stderr, "inotify_init failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	if (inotify_add_watch(fd, NETNS_RUN_DIR, IN_CREATE | IN_DELETE) < 0) {
		fprintf(stderr, "inotify_add_watch failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	for(;;) {
		ssize_t len = read(fd, buf, sizeof(buf));
		if (len < 0) {
			fprintf(stderr, "read failed: %s\n",
				strerror(errno));
			return EXIT_FAILURE;
		}
		for (event = (struct inotify_event *)buf;
		     (char *)event < &buf[len];
		     event = (struct inotify_event *)((char *)event + sizeof(*event) + event->len)) {
			if (event->mask & IN_CREATE)
				printf("add %s\n", event->name);
			if (event->mask & IN_DELETE)
				printf("delete %s\n", event->name);
		}
	}
	return EXIT_SUCCESS;
}

int do_netns(int argc, char **argv)
{
	if (argc < 1)
		return netns_list(0, NULL);

	if ((matches(*argv, "list") == 0) || (matches(*argv, "show") == 0) ||
	    (matches(*argv, "lst") == 0))
		return netns_list(argc-1, argv+1);

	if (matches(*argv, "help") == 0)
		return usage();

	if (matches(*argv, "add") == 0)
		return netns_add(argc-1, argv+1);

	if (matches(*argv, "delete") == 0)
		return netns_delete(argc-1, argv+1);

	if (matches(*argv, "identify") == 0)
		return netns_identify(argc-1, argv+1);

	if (matches(*argv, "pids") == 0)
		return netns_pids(argc-1, argv+1);

	if (matches(*argv, "exec") == 0)
		return netns_exec(argc-1, argv+1);

	if (matches(*argv, "monitor") == 0)
		return netns_monitor(argc-1, argv+1);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip netns help\".\n", *argv);
	return EXIT_FAILURE;
}
