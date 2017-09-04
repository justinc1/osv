#include <stdio.h>
#include <stdlib.h>

void mybreak();
int connect_from_tcp_etablished_client(int fd, int fd_srv, ushort dport);
int accept_from_tcp_etablished_server(int fd, int fd_clnt, uint32_t peer_addr, ushort peer_port);

int ipby_server_alloc_sockinfo(int listen_fd,
	uint32_t my_addr, ushort my_port,
	uint32_t peer_addr, ushort peer_port);

int ipby_server_connect_sockinfo(int fd,
	uint32_t my_addr, ushort my_port,
	uint32_t peer_addr, ushort peer_port);




/*----------------------------------------------------------------------------*/
// Debugging helpers

extern "C" long gettid(); // from linux.cc

#define printf_early_func(args...) { \
    int pos = 0; \
    char str[512]; \
    pos += snprintf(str+pos, sizeof(str)-pos, "DBG tid=%5d %s:%d %s: ", \
        gettid(), __FILE__, __LINE__, __FUNCTION__); \
    pos += snprintf(str+pos, sizeof(str)-pos, args); \
    debug_early(str); \
}

#define printf_early(args...) { if (0) { printf_early_func(args); } }

//#define mydebug(fmt, ...) fprintf(stderr, "DBG tid=% 5d %s:%d %s: " fmt, gettid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define mydebug(args...) { if (0) { printf_early_func(args); } }

extern const char* dbg_short_file(const char* path);
//#define __FILE_S__ dbg_short_file(__FILE__)
//#define fprintf_pos(ff, fmt, ...) { fprintf(ff, "DBG tid=% 5d %s:%d %s " fmt,  gettid(), dbg_short_file(__FILE__), __LINE__, __FUNCTION__, __VA_ARGS__ ); }
#define fprintf_pos(ff, fmt, ...) { if (0) { printf_early_func(fmt, ##__VA_ARGS__ ); } }
