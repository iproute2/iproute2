#ifndef __LWTUNNEL_H__
#define __LETUNNEL_H__ 1

int lwt_parse_encap(struct rtattr *rta, size_t len, int *argcp, char ***argvp);
void lwt_print_encap(FILE *fp, struct rtattr *encap_type,
		     struct rtattr *encap);

#endif
