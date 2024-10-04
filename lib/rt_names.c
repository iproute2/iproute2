/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * rt_names.c		rtnetlink names DB.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include <asm/types.h>
#include <linux/rtnetlink.h>

#include "rt_names.h"
#include "utils.h"

#define NAME_MAX_LEN 512

int numeric;

struct rtnl_hash_entry {
	struct rtnl_hash_entry	*next;
	const char		*name;
	unsigned int		id;
};

static int fread_id_name(FILE *fp, int *id, char *namebuf)
{
	char buf[NAME_MAX_LEN];

	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;

		while (*p == ' ' || *p == '\t')
			p++;

		if (*p == '#' || *p == '\n' || *p == 0)
			continue;

		if (sscanf(p, "0x%x %s\n", id, namebuf) != 2 &&
				sscanf(p, "0x%x %s #", id, namebuf) != 2 &&
				sscanf(p, "%d %s\n", id, namebuf) != 2 &&
				sscanf(p, "%d %s #", id, namebuf) != 2) {
			strcpy(namebuf, p);
			return -1;
		}
		return 1;
	}
	return 0;
}

static int
rtnl_hash_initialize(const char *file, struct rtnl_hash_entry **hash, int size)
{
	struct rtnl_hash_entry *entry;
	FILE *fp;
	int id;
	char namebuf[NAME_MAX_LEN] = {0};
	int ret;

	fp = fopen(file, "r");
	if (!fp)
		return -errno;

	while ((ret = fread_id_name(fp, &id, &namebuf[0]))) {
		if (ret == -1) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
					file, namebuf);
			fclose(fp);
			return -EINVAL;
		}

		if (id < 0)
			continue;

		entry = malloc(sizeof(*entry));
		if (entry == NULL) {
			fprintf(stderr, "malloc error: for entry\n");
			break;
		}
		entry->id   = id;
		entry->name = strdup(namebuf);
		entry->next = hash[id & (size - 1)];
		hash[id & (size - 1)] = entry;
	}
	fclose(fp);

	return 0;
}

static int rtnl_tab_initialize(const char *file, char **tab, int size)
{
	FILE *fp;
	int id;
	char namebuf[NAME_MAX_LEN] = {0};
	int ret;

	fp = fopen(file, "r");
	if (!fp)
		return -errno;

	while ((ret = fread_id_name(fp, &id, &namebuf[0]))) {
		if (ret == -1) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
					file, namebuf);
			fclose(fp);
			return -EINVAL;
		}
		if (id < 0 || id > size)
			continue;

		tab[id] = strdup(namebuf);
	}
	fclose(fp);

	return 0;
}

static char *rtnl_rtprot_tab[256] = {
	[RTPROT_UNSPEC]	    = "unspec",
	[RTPROT_REDIRECT]   = "redirect",
	[RTPROT_KERNEL]	    = "kernel",
	[RTPROT_BOOT]	    = "boot",
	[RTPROT_STATIC]	    = "static",

	[RTPROT_GATED]	    = "gated",
	[RTPROT_RA]	    = "ra",
	[RTPROT_MRT]	    = "mrt",
	[RTPROT_ZEBRA]	    = "zebra",
	[RTPROT_BIRD]	    = "bird",
	[RTPROT_BABEL]	    = "babel",
	[RTPROT_DNROUTED]   = "dnrouted",
	[RTPROT_XORP]	    = "xorp",
	[RTPROT_NTK]	    = "ntk",
	[RTPROT_DHCP]	    = "dhcp",
	[RTPROT_KEEPALIVED] = "keepalived",
	[RTPROT_BGP]	    = "bgp",
	[RTPROT_ISIS]	    = "isis",
	[RTPROT_OSPF]	    = "ospf",
	[RTPROT_RIP]	    = "rip",
	[RTPROT_EIGRP]	    = "eigrp",
};

struct tabhash {
	enum { TAB, HASH } type;
	union tab_or_hash {
		char **tab;
		struct rtnl_hash_entry **hash;
	} data;
};

static void
rtnl_tabhash_readdir(const char *dirpath_base, const char *dirpath_overload,
		     const struct tabhash tabhash, const int size)
{
	struct dirent *de;
	DIR *d;

	d = opendir(dirpath_base);
	while (d && (de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		size_t len;
		struct stat sb;

		if (*de->d_name == '.')
			continue;

		/* only consider filenames ending in '.conf' */
		len = strlen(de->d_name);
		if (len <= 5)
			continue;
		if (strcmp(de->d_name + len - 5, ".conf"))
			continue;

		if (dirpath_overload) {
			/* only consider filenames not present in
			   the overloading directory, e.g. /etc */
			snprintf(path, sizeof(path), "%s/%s", dirpath_overload, de->d_name);
			if (lstat(path, &sb) == 0)
				continue;
		}

		/* load the conf file in the base directory, e.g., /usr */
		snprintf(path, sizeof(path), "%s/%s", dirpath_base, de->d_name);
		if (tabhash.type == TAB)
			rtnl_tab_initialize(path, tabhash.data.tab, size);
		else
			rtnl_hash_initialize(path, tabhash.data.hash, size);
	}
	if (d)
		closedir(d);
}

static void
rtnl_tabhash_initialize_dir(const char *ddir, const struct tabhash tabhash, const int size)
{
	char dirpath_usr[PATH_MAX], dirpath_etc[PATH_MAX];

	snprintf(dirpath_usr, sizeof(dirpath_usr), "%s/%s", CONF_USR_DIR, ddir);
	snprintf(dirpath_etc, sizeof(dirpath_etc), "%s/%s", CONF_ETC_DIR, ddir);

	/* load /usr/lib/iproute2/foo.d/X conf files, unless /etc/iproute2/foo.d/X exists */
	rtnl_tabhash_readdir(dirpath_usr, dirpath_etc, tabhash, size);

	/* load /etc/iproute2/foo.d/X conf files */
	rtnl_tabhash_readdir(dirpath_etc, NULL, tabhash, size);
}

static void
rtnl_tab_initialize_dir(const char *ddir, char **tab, const int size)
{
	struct tabhash tab_data = {.type = TAB, .data.tab = tab};
	rtnl_tabhash_initialize_dir(ddir, tab_data, size);
}

static void
rtnl_hash_initialize_dir(const char *ddir, struct rtnl_hash_entry **hash,
			 const int size) {
	struct tabhash hash_data = {.type = HASH, .data.hash = hash};
	rtnl_tabhash_initialize_dir(ddir, hash_data, size);
}

static int rtnl_rtprot_init;

static void rtnl_rtprot_initialize(void)
{
	int ret;

	rtnl_rtprot_init = 1;
	ret = rtnl_tab_initialize(CONF_ETC_DIR "/rt_protos",
				  rtnl_rtprot_tab, 256);
	if (ret == -ENOENT)
		rtnl_tab_initialize(CONF_USR_DIR "/rt_protos",
				    rtnl_rtprot_tab, 256);

	rtnl_tab_initialize_dir("rt_protos.d", rtnl_rtprot_tab, 256);
}

const char *rtnl_rtprot_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= 256 || numeric) {
		snprintf(buf, len, "%u", id);
		return buf;
	}
	if (!rtnl_rtprot_tab[id]) {
		if (!rtnl_rtprot_init)
			rtnl_rtprot_initialize();
	}
	if (rtnl_rtprot_tab[id])
		return rtnl_rtprot_tab[id];
	snprintf(buf, len, "%u", id);
	return buf;
}

int rtnl_rtprot_a2n(__u32 *id, const char *arg)
{
	static char *cache;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtprot_init)
		rtnl_rtprot_initialize();

	for (i = 0; i < 256; i++) {
		if (rtnl_rtprot_tab[i] &&
		    strcmp(rtnl_rtprot_tab[i], arg) == 0) {
			cache = rtnl_rtprot_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}


static char *rtnl_addrprot_tab[256] = {
	[IFAPROT_UNSPEC]    = "unspec",
	[IFAPROT_KERNEL_LO] = "kernel_lo",
	[IFAPROT_KERNEL_RA] = "kernel_ra",
	[IFAPROT_KERNEL_LL] = "kernel_ll",
};
static bool rtnl_addrprot_tab_initialized;

static void rtnl_addrprot_initialize(void)
{
	int ret;

	rtnl_addrprot_tab_initialized = true;

	ret = rtnl_tab_initialize(CONF_ETC_DIR "/rt_addrprotos",
				  rtnl_addrprot_tab,
				  ARRAY_SIZE(rtnl_addrprot_tab));
	if (ret == -ENOENT)
		ret = rtnl_tab_initialize(CONF_USR_DIR "/rt_addrprotos",
					  rtnl_addrprot_tab,
					  ARRAY_SIZE(rtnl_addrprot_tab));

	rtnl_tab_initialize_dir("rt_addrprotos.d", rtnl_addrprot_tab,
				ARRAY_SIZE(rtnl_addrprot_tab));
}

const char *rtnl_addrprot_n2a(__u8 id, char *buf, int len)
{
	if (numeric)
		goto numeric;
	if (!rtnl_addrprot_tab_initialized)
		rtnl_addrprot_initialize();
	if (rtnl_addrprot_tab[id])
		return rtnl_addrprot_tab[id];
numeric:
	snprintf(buf, len, "%#x", id);
	return buf;
}

int rtnl_addrprot_a2n(__u8 *id, const char *arg)
{
	unsigned long res;
	char *end;
	int i;

	if (!rtnl_addrprot_tab_initialized)
		rtnl_addrprot_initialize();

	for (i = 0; i < 256; i++) {
		if (rtnl_addrprot_tab[i] &&
		    strcmp(rtnl_addrprot_tab[i], arg) == 0) {
			*id = i;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}


static char *rtnl_rtscope_tab[256] = {
	[RT_SCOPE_UNIVERSE]	= "global",
	[RT_SCOPE_NOWHERE]	= "nowhere",
	[RT_SCOPE_HOST]		= "host",
	[RT_SCOPE_LINK]		= "link",
	[RT_SCOPE_SITE]		= "site",
};

static int rtnl_rtscope_init;

static void rtnl_rtscope_initialize(void)
{
	int ret;

	rtnl_rtscope_init = 1;
	ret = rtnl_tab_initialize(CONF_ETC_DIR "/rt_scopes",
				  rtnl_rtscope_tab, 256);
	if (ret == -ENOENT)
		rtnl_tab_initialize(CONF_USR_DIR "/rt_scopes",
				    rtnl_rtscope_tab, 256);
}

const char *rtnl_rtscope_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= 256 || numeric) {
		snprintf(buf, len, "%d", id);
		return buf;
	}

	if (!rtnl_rtscope_tab[id]) {
		if (!rtnl_rtscope_init)
			rtnl_rtscope_initialize();
	}

	if (rtnl_rtscope_tab[id])
		return rtnl_rtscope_tab[id];

	snprintf(buf, len, "%d", id);
	return buf;
}

int rtnl_rtscope_a2n(__u32 *id, const char *arg)
{
	static const char *cache;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtscope_init)
		rtnl_rtscope_initialize();

	for (i = 0; i < 256; i++) {
		if (rtnl_rtscope_tab[i] &&
		    strcmp(rtnl_rtscope_tab[i], arg) == 0) {
			cache = rtnl_rtscope_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}


static char *rtnl_rtrealm_tab[256] = {
	"unknown",
};

static int rtnl_rtrealm_init;

static void rtnl_rtrealm_initialize(void)
{
	int ret;

	rtnl_rtrealm_init = 1;
	ret = rtnl_tab_initialize(CONF_ETC_DIR "/rt_realms",
				  rtnl_rtrealm_tab, 256);
	if (ret == -ENOENT)
		rtnl_tab_initialize(CONF_USR_DIR "/rt_realms",
				    rtnl_rtrealm_tab, 256);
}

const char *rtnl_rtrealm_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= 256 || numeric) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtrealm_tab[id]) {
		if (!rtnl_rtrealm_init)
			rtnl_rtrealm_initialize();
	}
	if (rtnl_rtrealm_tab[id])
		return rtnl_rtrealm_tab[id];
	snprintf(buf, len, "%d", id);
	return buf;
}


int rtnl_rtrealm_a2n(__u32 *id, const char *arg)
{
	static char *cache;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtrealm_init)
		rtnl_rtrealm_initialize();

	for (i = 0; i < 256; i++) {
		if (rtnl_rtrealm_tab[i] &&
		    strcmp(rtnl_rtrealm_tab[i], arg) == 0) {
			cache = rtnl_rtrealm_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}


static struct rtnl_hash_entry dflt_table_entry  = { .name = "default" };
static struct rtnl_hash_entry main_table_entry  = { .name = "main" };
static struct rtnl_hash_entry local_table_entry = { .name = "local" };

static struct rtnl_hash_entry *rtnl_rttable_hash[256] = {
	[RT_TABLE_DEFAULT] = &dflt_table_entry,
	[RT_TABLE_MAIN]    = &main_table_entry,
	[RT_TABLE_LOCAL]   = &local_table_entry,
};

static int rtnl_rttable_init;

static void rtnl_rttable_initialize(void)
{
	int i;
	int ret;

	rtnl_rttable_init = 1;
	for (i = 0; i < 256; i++) {
		if (rtnl_rttable_hash[i])
			rtnl_rttable_hash[i]->id = i;
	}
	ret = rtnl_hash_initialize(CONF_ETC_DIR "/rt_tables",
				   rtnl_rttable_hash, 256);
	if (ret == -ENOENT)
		rtnl_hash_initialize(CONF_USR_DIR "/rt_tables",
				     rtnl_rttable_hash, 256);

	rtnl_hash_initialize_dir("rt_tables.d", rtnl_rttable_hash, 256);
}

const char *rtnl_rttable_n2a(__u32 id, char *buf, int len)
{
	struct rtnl_hash_entry *entry;

	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();
	entry = rtnl_rttable_hash[id & 255];
	while (entry && entry->id != id)
		entry = entry->next;
	if (!numeric && entry)
		return entry->name;
	snprintf(buf, len, "%u", id);
	return buf;
}

int rtnl_rttable_a2n(__u32 *id, const char *arg)
{
	static const char *cache;
	static unsigned long res;
	struct rtnl_hash_entry *entry;
	char *end;
	unsigned long i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();

	for (i = 0; i < 256; i++) {
		entry = rtnl_rttable_hash[i];
		while (entry && strcmp(entry->name, arg))
			entry = entry->next;
		if (entry) {
			cache = entry->name;
			res = entry->id;
			*id = res;
			return 0;
		}
	}

	i = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || i > RT_TABLE_MAX)
		return -1;
	*id = i;
	return 0;
}


static char *rtnl_rtdsfield_tab[256] = {
	"0",
};

static int rtnl_rtdsfield_init;

static void rtnl_rtdsfield_initialize(void)
{
	int ret;

	rtnl_rtdsfield_init = 1;
	ret = rtnl_tab_initialize(CONF_ETC_DIR "/rt_dsfield",
				  rtnl_rtdsfield_tab, 256);
	if (ret == -ENOENT)
		rtnl_tab_initialize(CONF_USR_DIR "/rt_dsfield",
				    rtnl_rtdsfield_tab, 256);
}

const char *rtnl_dsfield_n2a(int id, char *buf, int len)
{
	const char *name;

	if (id < 0 || id >= 256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!numeric) {
		name = rtnl_dsfield_get_name(id);
		if (name != NULL)
			return name;
	}
	snprintf(buf, len, "0x%02x", id);
	return buf;
}

const char *rtnl_dsfield_get_name(int id)
{
	if (id < 0 || id >= 256)
		return NULL;
	if (!rtnl_rtdsfield_tab[id]) {
		if (!rtnl_rtdsfield_init)
			rtnl_rtdsfield_initialize();
	}
	return rtnl_rtdsfield_tab[id];
}

const char *rtnl_dscp_n2a(int id, char *buf, int len)
{
	if (!numeric) {
		const char *name = rtnl_dsfield_get_name(id << 2);

		if (name != NULL)
			return name;
	}
	snprintf(buf, len, "%u", id);
	return buf;
}

int rtnl_dsfield_a2n(__u32 *id, const char *arg)
{
	static char *cache;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtdsfield_init)
		rtnl_rtdsfield_initialize();

	for (i = 0; i < 256; i++) {
		if (rtnl_rtdsfield_tab[i] &&
		    strcmp(rtnl_rtdsfield_tab[i], arg) == 0) {
			cache = rtnl_rtdsfield_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 16);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}

int rtnl_dscp_a2n(__u32 *id, const char *arg)
{
	if (get_u32(id, arg, 0) == 0)
		return 0;

	if (rtnl_dsfield_a2n(id, arg) != 0)
		return -1;
	/* Convert from DS field to DSCP */
	*id >>= 2;

	return 0;
}

static struct rtnl_hash_entry dflt_group_entry = {
	.id = 0, .name = "default"
};

static struct rtnl_hash_entry *rtnl_group_hash[256] = {
	[0] = &dflt_group_entry,
};

static int rtnl_group_init;

static void rtnl_group_initialize(void)
{
	int ret;

	rtnl_group_init = 1;
	ret = rtnl_hash_initialize(CONF_ETC_DIR "/group",
				   rtnl_group_hash, 256);
	if (ret == -ENOENT)
		rtnl_hash_initialize(CONF_USR_DIR "/group",
				     rtnl_group_hash, 256);
}

int rtnl_group_a2n(int *id, const char *arg)
{
	static const char *cache;
	static unsigned long res;
	struct rtnl_hash_entry *entry;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_group_init)
		rtnl_group_initialize();

	for (i = 0; i < 256; i++) {
		entry = rtnl_group_hash[i];
		while (entry && strcmp(entry->name, arg))
			entry = entry->next;
		if (entry) {
			cache = entry->name;
			res = entry->id;
			*id = res;
			return 0;
		}
	}

	i = strtol(arg, &end, 0);
	if (!end || end == arg || *end || i < 0)
		return -1;
	*id = i;
	return 0;
}

const char *rtnl_group_n2a(int id, char *buf, int len)
{
	struct rtnl_hash_entry *entry;
	int i;

	if (!rtnl_group_init)
		rtnl_group_initialize();

	for (i = 0; !numeric && i < 256; i++) {
		entry = rtnl_group_hash[i];

		while (entry) {
			if (entry->id == id)
				return entry->name;
			entry = entry->next;
		}
	}

	snprintf(buf, len, "%d", id);
	return buf;
}

static char *nl_proto_tab[256] = {
	[NETLINK_ROUTE]          = "rtnl",
	[NETLINK_UNUSED]         = "unused",
	[NETLINK_USERSOCK]       = "usersock",
	[NETLINK_FIREWALL]       = "fw",
	[NETLINK_SOCK_DIAG]      = "tcpdiag",
	[NETLINK_NFLOG]          = "nflog",
	[NETLINK_XFRM]           = "xfrm",
	[NETLINK_SELINUX]        = "selinux",
	[NETLINK_ISCSI]          = "iscsi",
	[NETLINK_AUDIT]          = "audit",
	[NETLINK_FIB_LOOKUP]     = "fiblookup",
	[NETLINK_CONNECTOR]      = "connector",
	[NETLINK_NETFILTER]      = "nft",
	[NETLINK_IP6_FW]         = "ip6fw",
	[NETLINK_DNRTMSG]        = "dec-rt",
	[NETLINK_KOBJECT_UEVENT] = "uevent",
	[NETLINK_GENERIC]        = "genl",
	[NETLINK_SCSITRANSPORT]  = "scsi-trans",
	[NETLINK_ECRYPTFS]       = "ecryptfs",
	[NETLINK_RDMA]           = "rdma",
	[NETLINK_CRYPTO]         = "crypto",
};

static int nl_proto_init;

static void nl_proto_initialize(void)
{
	int ret;

	nl_proto_init = 1;
	ret = rtnl_tab_initialize(CONF_ETC_DIR "/nl_protos",
				  nl_proto_tab, 256);
	if (ret == -ENOENT)
		rtnl_tab_initialize(CONF_USR_DIR "/nl_protos",
				    nl_proto_tab, 256);
}

const char *nl_proto_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= 256 || numeric) {
		snprintf(buf, len, "%d", id);
		return buf;
	}

	if (!nl_proto_init)
		nl_proto_initialize();

	if (nl_proto_tab[id])
		return nl_proto_tab[id];

	snprintf(buf, len, "%u", id);
	return buf;
}

int nl_proto_a2n(__u32 *id, const char *arg)
{
	static char *cache;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!nl_proto_init)
		nl_proto_initialize();

	for (i = 0; i < 256; i++) {
		if (nl_proto_tab[i] &&
		    strcmp(nl_proto_tab[i], arg) == 0) {
			cache = nl_proto_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}

#define PROTODOWN_REASON_NUM_BITS 32
static char *protodown_reason_tab[PROTODOWN_REASON_NUM_BITS] = {
};

static int protodown_reason_init;

static void protodown_reason_initialize(void)
{
	protodown_reason_init = 1;

	rtnl_tab_initialize_dir("protodown_reasons.d", protodown_reason_tab,
				PROTODOWN_REASON_NUM_BITS);
}

int protodown_reason_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= PROTODOWN_REASON_NUM_BITS)
		return -1;

	if (numeric) {
		snprintf(buf, len, "%d", id);
		return 0;
	}

	if (!protodown_reason_init)
		protodown_reason_initialize();

	if (protodown_reason_tab[id])
		snprintf(buf, len, "%s", protodown_reason_tab[id]);
	else
		snprintf(buf, len, "%d", id);

	return 0;
}

int protodown_reason_a2n(__u32 *id, const char *arg)
{
	static char *cache;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!protodown_reason_init)
		protodown_reason_initialize();

	for (i = 0; i < PROTODOWN_REASON_NUM_BITS; i++) {
		if (protodown_reason_tab[i] &&
		    strcmp(protodown_reason_tab[i], arg) == 0) {
			cache = protodown_reason_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res >= PROTODOWN_REASON_NUM_BITS)
		return -1;
	*id = res;
	return 0;
}
