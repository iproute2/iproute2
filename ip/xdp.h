#ifndef __XDP__
#define __XDP__

#include "utils.h"

int xdp_parse(int *argc, char ***argv, struct iplink_req *req, bool generic);
void xdp_dump(FILE *fp, struct rtattr *tb);

#endif /* __XDP__ */
