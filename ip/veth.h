int do_veth(int argc, char **argv);

enum {
	VETH_CMD_UNSPEC, 
	VETH_CMD_ADD, 
	VETH_CMD_DEL,

	VETH_CMD_MAX
};

enum {
	VETH_ATTR_UNSPEC,
	VETH_ATTR_DEVNAME,
	VETH_ATTR_PEERNAME,

	VETH_ATTR_MAX
};
