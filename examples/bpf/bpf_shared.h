#ifndef __BPF_SHARED__
#define __BPF_SHARED__

enum {
	BPF_MAP_ID_PROTO,
	BPF_MAP_ID_QUEUE,
	BPF_MAP_ID_DROPS,
	__BPF_MAP_ID_MAX,
#define BPF_MAP_ID_MAX	__BPF_MAP_ID_MAX
};

struct count_tuple {
	long packets; /* type long for lock_xadd() */
	long bytes;
};

struct count_queue {
	long total;
	long mismatch;
};

#endif /* __BPF_SHARED__ */
