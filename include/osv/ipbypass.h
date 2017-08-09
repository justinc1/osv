#include <stdio.h>
#include <stdlib.h>

long int gettid();
#define debug(fmt, ...) if(1) { fprintf(stderr, "DBG tid=% 5d %s:%d %s: " fmt, gettid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); }

void mybreak();
int connect_from_tcp_etablished_client(int fd, int fd_srv, ushort dport);
int accept_from_tcp_etablished_server(int fd, int fd_clnt, uint32_t peer_addr, ushort peer_port);

