#ifndef __COLOR_H__
#define __COLOR_H__ 1

enum color_attr {
	COLOR_IFNAME,
	COLOR_MAC,
	COLOR_INET,
	COLOR_INET6,
	COLOR_OPERSTATE_UP,
	COLOR_OPERSTATE_DOWN,
	COLOR_NONE
};

void enable_color(void);
void check_if_color_enabled(void);
void set_color_palette(void);
int color_fprintf(FILE *fp, enum color_attr attr, const char *fmt, ...);
enum color_attr ifa_family_color(__u8 ifa_family);
enum color_attr oper_state_color(__u8 state);

#endif
