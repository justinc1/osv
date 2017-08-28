#include <stdio.h>
#include <stdlib.h>

void mybreak();
int connect_from_tcp_etablished_client(int fd, int fd_srv, ushort dport);
int accept_from_tcp_etablished_server(int fd, int fd_clnt, uint32_t peer_addr, ushort peer_port);


/*----------------------------------------------------------------------------*/
// Debugging helpers

long int gettid();
#define mydebug(fmt, ...) if(0) { fprintf(stderr, "DBG tid=% 5d %s:%d %s: " fmt, gettid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); }

#define printf_early(args...) { \
	if (0) { \
    int pos = 0; \
    char str[2000]; \
    pos += snprintf(str+pos, sizeof(str)-pos, "DBG tid=%5d %s:%d %s: ", \
        gettid(), __FILE__, __LINE__, __FUNCTION__); \
    pos += snprintf(str+pos, sizeof(str)-pos, args); \
    debug_early(str); \
	} \
}
