#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <bsd/uipc_syscalls.h>
#include <osv/debug.h>
#include "libc/af_local.h"

#include "libc/internal/libc.h"

#define sock_d(...)		tprintf_d("socket-api", __VA_ARGS__);

/*--------------------------------------------------------------------------*/
#include "osv/debug.hh"
#include <boost/circular_buffer.hpp>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */

bool in_range(size_t val, size_t low, size_t high)
{
	if (high>low) {
		return low <= val && val < high;
	}
	else {
		return low <= val || val < high;
	}
}

class RingBuffer {
public:
	RingBuffer();
	void alloc(size_t len);
	size_t push(const void* buf, size_t len);
	size_t pop(void* buf, size_t len);
	size_t available_read();
	size_t available_write();
public:
	char* data;
	size_t length;
	volatile size_t rpos;
	volatile size_t wpos;
public:
};


RingBuffer::RingBuffer()
{
	data = nullptr;
	length = 0;
	rpos = 0;
	wpos = 0;
}

void RingBuffer::alloc(size_t len)
{
	assert(data == nullptr);
	assert(length == 0);
	data = (char*)malloc(len);
	if (!data)
		return;
	memset(data, 0x00, len);
	length = len;
	rpos = 0;
	wpos = 0;
}

size_t RingBuffer::available_read() {
	size_t len;
	len = wpos - rpos;
	if (len<0)
		len += length;
	return len;
	assert(0 <= len);
	assert(len <= length);
}

size_t RingBuffer::available_write() {
	return length - available_read();
}

size_t RingBuffer::push(const void* buf, size_t len)
{
	size_t wpos2, len1, len2;
	len = len % length; // so at most one wrap-around will occur.
	wpos2 = wpos + len;
	if (wpos2 <= length) {
		memcpy(data + wpos, buf, len);
		wpos = wpos2;
	}
	else {
		len1 = length - wpos;
		len2 = len - len1;
		memcpy(data + wpos, buf, len1);
		memcpy(data, buf + len1, len2);
		wpos = len2;
	}
	return len;
}

size_t RingBuffer::pop(void* buf, size_t len)
{
	size_t rpos2, len1, len2;
	size_t readable_len = available_read();
	len = std::min(len, length); // so at most one wrap-around will occur.
	len = std::min(len, readable_len);
	rpos2 = rpos + len;
	if (rpos2 <= length) {
		memcpy(data + rpos, buf, len);
		rpos = rpos2;
	}
	else {
		len1 = length - rpos;
		len2 = len - len1;
		memcpy(data + rpos, buf, len1);
		memcpy(data, buf + len1, len2);
		rpos = len2;
	}
	return len;
}

/*--------------------------------------------------------------------------*/

class sock_info {
public:
	sock_info();
	void bypass(uint32_t peer_addr=0xFFFFFFFF, ushort peer_port=0);
	size_t data_push(const void* buf, size_t len);
	size_t data_pop(void* buf, size_t len);
public:
	int fd;
	bool is_bypass;
	// should be ivshmem ring or virtio ring
	
	//boost::circular_buffer<char> in_buf;
	RingBuffer ring_buf;
	
	// who are my peers - they are supposed to write into in_buf;
	// peers are identified by - by what?
	//  - peer fd - it makes sense only when we are inside the same VM
	//  - proto, src ip, src port, dest ip, dest port.
	// ignore SOCK_DGRAM vs SOCK_STREAM
	int my_proto; // IPPROTO_UDP or IPPROTO_TCP
	// addr and port are in network byte order
	uint32_t my_addr;
	ushort my_port;
	// peer this socket is connected to. Note - our peer can be connected by/from multiple clients.
	uint32_t peer_addr;
	ushort peer_port;
};

sock_info::sock_info() {
	fd = -1;
	is_bypass = false;
	my_proto = -1;
	my_addr = 0xFFFFFFFF;
	my_port = 0;
	peer_addr = 0xFFFFFFFF;
	peer_port = 0;
}

#define BYPASS_BUF_SZ (1024*1024)

void sock_info::bypass(uint32_t _peer_addr, ushort _peer_port) {
	if (!is_bypass) {
		is_bypass = true;
		peer_addr = _peer_addr;
		peer_port = _peer_port;
		//in_buf.set_capacity(BYPASS_BUF_SZ); // WTF - 16 je premajhna stevilka, in crashne ????? 16kB je OK.
		ring_buf.alloc(BYPASS_BUF_SZ);
		//fprintf_pos(stderr, "INFO fd=%d, in_buf size=%d capacity=%d reserve=%d\n",
		//	fd, in_buf.size(), in_buf.capacity(), in_buf.reserve() );
		fprintf_pos(stderr, "INFO fd=%d peer addr=0x%08x,port=%d\n",
			fd, ntohl(peer_addr), ntohs(peer_port));
	}
}

size_t sock_info::data_push(const void* buf, size_t len) {
	/*while (len > in_buf.reserve()) {
		usleep(1000*1100);
	}*/
	/*size_t ii;
	char ch;
	for(ii=0; ii<len; ii++) {
		ch = static_cast<const char*>(buf)[ii];
		in_buf.push_back(ch);
	}
	return len;
	*/
	return ring_buf.push(buf, len);
}

size_t sock_info::data_pop(void* buf, size_t len) {
	/*while (in_buf.size() <= 0) {
		// TODO atomicnost datagramov
		usleep(1000*1200);
	}*/
	/*
	size_t copy_len = std::min(len, in_buf.size());
	size_t ii;
	char ch;
	for(ii=0; ii<copy_len; ii++) {
		ch = in_buf[0];
		static_cast<char*>(buf)[ii] = ch;
		in_buf.pop_front();
	}
	return copy_len;
	*/
	return ring_buf.pop(buf, len);
}


// all sockets
std::vector<sock_info> so_list;

void sol_insert(int fd, int protocol) {
	sock_info soinf;
	soinf.fd = fd;
	soinf.my_proto = protocol;
	so_list.push_back(soinf);
}

sock_info* sol_find(int fd) {
	auto it = std::find_if(so_list.begin(), so_list.end(), 
		[&] (sock_info soinf) { return soinf.fd == fd; } );
	if (it == so_list.end()) {
		if(fd>2) {
			fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		}
		return nullptr;
	}
	return &(*it);
}

sock_info* sol_find_me(int fd, uint32_t my_addr, ushort my_port) {
	auto it = std::find_if(so_list.begin(), so_list.end(), 
		[&] (sock_info soinf) { 
			// protocol pa kar ignoriram, jejhetaja.
			return 	(soinf.my_addr == INADDR_ANY || soinf.my_addr == my_addr) &&
					(soinf.my_port == my_port);
		});
	if (it == so_list.end()) {
		fprintf_pos(stderr, "ERROR fd=%d me 0x%08x:%d not found\n", fd, ntohl(my_addr), ntohs(my_port));
		return nullptr;
	}
	return &(*it);
}
sock_info* sol_find_peer2(int fd, uint32_t peer_addr, ushort peer_port) {
	auto it = std::find_if(so_list.begin(), so_list.end(), 
		[&] (sock_info soinf) { 
			// protocol pa kar ignoriram, jejhetaja.
			int addr_match;
			//uint32_t my_iface_ip_addr = htonl( 0xc0a87a5a ); // 192.168.122.90 test VM ip :/
			addr_match = soinf.peer_addr == INADDR_ANY || 
				soinf.peer_addr == peer_addr ||
				//(peer_addr == my_iface_ip_addr) ||
				(peer_addr == INADDR_ANY); // tale pogoj bo pa napacen. ker zdaj bi 
			return addr_match && (soinf.peer_port == peer_port);
		});
	if (it == so_list.end()) {
		fprintf_pos(stderr, "ERROR fd=%d peer 0x%08x:%d not found\n", fd, ntohl(peer_addr), ntohs(peer_port));
		return nullptr;
	}
	return &(*it);
}
bool so_bypass_possible(sock_info* soinf, ushort port) {
	return false;
	bool do_bypass=false;
	// instead of searching for intra-host VMs, use bypass for magic port numbers only
	// iperf - port 5001
	// udprecv/udpsend - port 3333
	ushort pp;
	pp = htons(port);
	if ((3330 <= pp && pp <= 3340) || 
		(5000 <= pp && pp <= 5010) ) {
		do_bypass = true;
	}
	return do_bypass;
}

size_t soi_data_len(int fd) {
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr)
		return 0;
	//return soinf->in_buf.size();
	return soinf->ring_buf.available_read();
}

bool soi_is_bypassed(sock_info* soinf) {
	if (!soinf)
		return false;
	return soinf->is_bypass;
}


//iperf crkne , ker select javi timeout :/   ??
//glej Client.cpp Client::write_UDP_FIN


/*--------------------------------------------------------------------------*/

extern "C"
int socketpair(int domain, int type, int protocol, int sv[2])
{
	int error;

	sock_d("socketpair(domain=%d, type=%d, protocol=%d)", domain, type,
		protocol);

	if (domain == AF_LOCAL)
		return socketpair_af_local(type, protocol, sv);

	error = linux_socketpair(domain, type, protocol, sv);
	if (error) {
		sock_d("socketpair() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int getsockname(int sockfd, struct bsd_sockaddr *addr, socklen_t *addrlen)
{
	int error;

	sock_d("getsockname(sockfd=%d, ...)", sockfd);

	error = linux_getsockname(sockfd, addr, addrlen);
	if (error) {
		sock_d("getsockname() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int getpeername(int sockfd, struct bsd_sockaddr *addr, socklen_t *addrlen)
{
	int error;

	sock_d("getpeername(sockfd=%d, ...)", sockfd);

	error = linux_getpeername(sockfd, addr, addrlen);
	if (error) {
		sock_d("getpeername() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int accept4(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len, int flg)
{
	int fd2, error;

	sock_d("accept4(fd=%d, ..., flg=%d)", fd, flg);

	error = linux_accept4(fd, addr, len, &fd2, flg);
	if (error) {
		sock_d("accept4() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return fd2;
}

extern "C"
int accept(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len)
{
	int fd2, error;

	sock_d("accept(fd=%d, ...)", fd);

	error = linux_accept(fd, addr, len, &fd2);
	if (error) {
		sock_d("accept() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return fd2;
}

extern "C"
int bind(int fd, const struct bsd_sockaddr *addr, socklen_t len)
{
	int error;

	sock_d("bind(fd=%d, ...)", fd);

	error = linux_bind(fd, (void *)addr, len);
	if (error) {
		sock_d("bind() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return -1;
	}
	struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
	soinf->my_addr = in_addr->sin_addr.s_addr;
	soinf->my_port = in_addr->sin_port;
	fprintf_pos(stderr, "fd=%d me 0x%08x:%d\n", fd, ntohl(soinf->my_addr), ntohs(soinf->my_port));

	// enable bypass for all server-side sockets.
	// But not to early.
	//soinf->bypass();


#if 0
	// soinf->my_addr = ((sockaddr_in*)(addr))->sin_addr.s_addr;
	// soinf->my_port = ((sockaddr_in*)(addr))->sin_port;

	// connect linux_connect kern_connect
	// so->so_proto->pr_flags & PR_CONNREQUIRED ; // iz soconnect()
	//bind linux_bind kern_bind

linux_bind(int s, void *name, int namelen)
	struct bsd_sockaddr *sa;
	int error;
	error = linux_getsockaddr(&sa, (const bsd_osockaddr*)name, namelen);
	if (error)
		return (error);
	error = kern_bind(s, sa);

#endif

#if 0
	// linux_connect
	struct bsd_sockaddr *sa;
	int error;
	error = linux_getsockaddr(&sa, (const bsd_osockaddr*)addr, len);
	if (error)
		return (error);
	error = kern_connect(s, sa);

	// kern_connect
	struct socket *so;
	struct file *fp;
	int error;
	int interrupted = 0;
	error = getsock_cap(fd, &fp, NULL);
	if (error)
		return (error);
	so = (socket*)file_data(fp);
#endif

	return 0;
}

extern "C"
int connect(int fd, const struct bsd_sockaddr *addr, socklen_t len)
{
	int error;

	sock_d("connect(fd=%d, ...)", fd);
	fprintf_pos(stderr, "INFO connect fd=%d\n", fd);

	/* ta connect crkne, ce je to UDP server - t.j. bind, nato connect. Vmes moras vsaj en paket prejeti? */
	error = linux_connect(fd, (void *)addr, len);
	if (error) {
		sock_d("connect() failed, errno=%d", error);
		fprintf_pos(stderr, "ERROR connect() failed, errno=%d\n", error);
		errno = error;
		return -1;
	}

	// if we connect to intra-host VM, use bypass
	// OR, if we connect to the same-VM, use bypass
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return -1;
	}

	struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
	uint32_t peer_addr = in_addr->sin_addr.s_addr;
	ushort peer_port = in_addr->sin_port;
	fprintf_pos(stderr, "INFO connect fd=%d peer addr=0x%08x,port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));
	if (so_bypass_possible(soinf, soinf->my_port) ||
		so_bypass_possible(soinf, peer_port)) {
		fprintf_pos(stderr, "INFO connect fd=%d me=0x%08x:%d peer 0x%08x:%d try to bypass\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		// soinf->bypass(peer_addr, peer_port);
		soinf->peer_addr = peer_addr;
		soinf->peer_port = peer_port;
	}
	else {
		fprintf_pos(stderr, "INFO connect fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	}
	
	return 0;
}

extern "C"
int listen(int fd, int backlog)
{
	int error;

	sock_d("listen(fd=%d, backlog=%d)", fd, backlog);

	error = linux_listen(fd, backlog);
	if (error) {
		sock_d("listen() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

// uipc_syscals.cc
#include <sys/cdefs.h>

#include <bsd/porting/netport.h>
#include <bsd/uipc_syscalls.h>

#include <fcntl.h>
#include <osv/fcntl.h>
#include <osv/ioctl.h>
#include <errno.h>

#include <bsd/sys/sys/param.h>
#include <bsd/porting/synch.h>
#include <osv/file.h>
#include <osv/socket.hh>

#include <bsd/sys/sys/mbuf.h>
#include <bsd/sys/sys/protosw.h>
#include <bsd/sys/sys/socket.h>
#include <bsd/sys/sys/socketvar.h>
#include <osv/uio.h>
#include <bsd/sys/net/vnet.h>

#include <memory>
#include <fs/fs.hh>

#include <osv/defer.hh>
#include <osv/mempool.hh>
#include <osv/pagealloc.hh>
#include <osv/zcopy.hh>
#include <sys/eventfd.h>
int getsock_cap(int fd, struct file **fpp, u_int *fflagp);

ssize_t recvfrom_bypass(int fd, void *__restrict buf, size_t len)
{
 
	/*
	Zdaj bi moral hkrati cakati na podatke via bypass, ali pa via iface.
	Kar prej pride.

	Iface mi uporabi en waiter v sbwait(). A ga lahko reusam ?

	A bi moral
	*/

#if 0
	/* bsd/sys/kern/uipc_syscalls.cc:608 +- eps */
	struct file *fp;
	struct socket *so;
	struct bsd_sockaddr *fromsa = 0;
	if (controlp != NULL)
		*controlp = NULL;
	error = getsock_cap(s, &fp, NULL);
	if (error)
		return (error);
	so = (socket*)file_data(fp);

	/* bsd/sys/kern/uipc_socket.cc:2425 */
	error = sbwait(so, &so->so_rcv);
#endif

 	sock_info *soinf = sol_find(fd);
	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	if (soinf==NULL || !soinf->is_bypass) {
		return 0;
	}
	fprintf_pos(stderr, "BYPASS-ed\n", "");

	/* bsd/sys/kern/uipc_syscalls.cc:608 +- eps */
	int error;
	struct file *fp;
	struct socket *so;
	error = getsock_cap(fd, &fp, NULL);
	if (error)
		return (error);
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	SOCK_LOCK(so);
	error = sbwait(so, &so->so_rcv);
	//error = sbwait(so, &so->so_rcv); /* se obesi, oz dobim samo vsak drugi paket... */
	SOCK_UNLOCK(so);
	fdrop(fp); /* TODO PAZI !!! */

	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	size_t len2;
	len2 = soinf->data_pop(buf, len);
	return len2;

	return 0;
}

extern "C"
ssize_t recvfrom(int fd, void *__restrict buf, size_t len, int flags,
		struct bsd_sockaddr *__restrict addr, socklen_t *__restrict alen)
{
	int error;
	ssize_t bytes;

	sock_d("recvfrom(fd=%d, buf=<uninit>, len=%d, flags=0x%x, ...)", fd,
		len, flags);
 
	ssize_t len2 = recvfrom_bypass(fd, buf, len);
	if (len2)  {
		return len2;
	}

	// tudi tu se klice sbwait. IZgleda, da ne moti, da ponoven klic brez predhodnega branja podatkov takoj neha cakatai.
	error = linux_recvfrom(fd, (caddr_t)buf, len, flags, addr, alen, &bytes);
	if (error) {
		sock_d("recvfrom() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	// try to enable bypass after first received packet
 	sock_info *soinf = sol_find(fd);
	if(!soinf) {
		return bytes;
	}
	struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
	uint32_t peer_addr = in_addr->sin_addr.s_addr;
	ushort peer_port = in_addr->sin_port;
	fprintf_pos(stderr, "INFO fd=%d peer addr=0x%08x,port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));
	//
	// and enable for peer too.
	// But peer didn't save its port and addr :/
	// So I should search fore someone who has me as peer ?? mess mess mess
 	sock_info *peer_soinf = nullptr;
 	//peer_soinf = sol_find_peer2(fd, peer_addr, peer_port);
 	peer_soinf = sol_find_peer2(fd, soinf->my_addr, soinf->my_port); // search for socket, which is sending to me.

 	//
	if(!peer_soinf) {
		return bytes; //TODO_tole?
	}
	if (so_bypass_possible(soinf, soinf->my_port) ||
		so_bypass_possible(soinf, peer_port)) {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d try to bypass\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		soinf->bypass(peer_addr, peer_port);
		peer_soinf->bypass(peer_addr, peer_port);
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	}

	return bytes;
}

extern "C"
ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	int error;
	ssize_t bytes;

	sock_d("recv(fd=%d, buf=<uninit>, len=%d, flags=0x%x)", fd, len, flags);
	
	ssize_t len2 = recvfrom_bypass(fd, buf, len);
	if (len2)  {
		return len2;
	}
	
	error = linux_recv(fd, (caddr_t)buf, len, flags, &bytes);
	if (error) {
		sock_d("recv() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return bytes;
}

extern "C"
ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	ssize_t bytes;
	int error;

	sock_d("recvmsg(fd=%d, msg=..., flags=0x%x)", fd, flags);

	/*
	buff to iovec
	ssize_t len2 = recvfrom_bypass(fd, buf, len);
	if (len2)  {
		return len2;
	}*/

	error = linux_recvmsg(fd, msg, flags, &bytes);
	if (error) {
		sock_d("recvmsg() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return bytes;
}

ssize_t sendto_bypass(int fd, const void *buf, size_t len, int flags,
    const struct bsd_sockaddr *addr, socklen_t alen) {
	int error;
 	sock_info *soinf = sol_find(fd);
	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		return 0;
	}

	if (!soinf->is_bypass) {
		return 0;
	}

	uint32_t peer_addr = 0xFFFFFFFF;
	ushort peer_port = 0;
	if (addr) {
		struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
		peer_addr = in_addr->sin_addr.s_addr;
		peer_port = in_addr->sin_port;
	}
	else {
		// this should be connect-ed socket, so peer is known. Somewhere...
		peer_addr = soinf->peer_addr;
		peer_port = soinf->peer_port;
	}

	if (peer_addr == 0xFFFFFFFF && peer_port == 0) {
		return 0;
	}
	// OK, peer seems to be known and our.

	fprintf_pos(stderr, "BYPASS-ed\n", "");
	fprintf_pos(stderr, "peer_addr=0x%08x peer_port=%d\n", ntohl(peer_addr), ntohs(peer_port));
	// zdaj pa najdi enga, ki temu ustreza
	// CEL JEBENI ROUTING BI MORAL EVALUIRATI !!!!! fuck.
	// Pa - a naj gledam IP addr ali MAC addr ?
 	sock_info *soinf_peer = sol_find_me(fd, peer_addr, peer_port);
		size_t len2=0;
 	if (soinf_peer) {
			len2 = soinf_peer->data_push(buf, len);
		}
		else {
			//return 0; // samo da ne posljem pravega paketa, lazje debugiram
			return len; // itak da je uspelo
		}

	/* bsd/sys/kern/uipc_syscalls.cc:608 +- eps */
	struct file *fp;
	struct socket *so;
	error = getsock_cap(soinf_peer->fd, &fp, NULL);
	if (error)
		return (error);
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	SOCK_LOCK(so);
	//
	//error = sbwait(so, &so->so_rcv);
	so->so_nc_wq.wake_all(SOCK_MTX_REF(so));
	//
	SOCK_UNLOCK(so);
	fdrop(fp); /* TODO PAZI !!! */
	return len2;

	/*
	iz sbwait_tmo()
	sched::thread::wait_for(SOCK_MTX_REF(so), *so->so_nc, sb->sb_cc_wq, tmr, sc);
	so->so_nc_busy = false;
	so->so_nc_wq.wake_all(SOCK_MTX_REF(so));
	*/
}

// save peer addr/port just after first send
void sendto_bypass_part2(int fd)
{
	// try to enable bypass after first sent packet
	// NO, receiver might not be up yet.
	// So, receiver should enable bypass for sender, after he gets first packet.
	// Here, just save peer addr/port - so that we get "connected" like
	sock_info *soinf = sol_find(fd);
	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		return;
	}
	uint32_t peer_addr = soinf->peer_addr;
	ushort peer_port = soinf->peer_port;
	fprintf_pos(stderr, "INFO fd=%d peer addr=0x%08x,port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));
	if (so_bypass_possible(soinf, soinf->my_port) ||
		so_bypass_possible(soinf, peer_port)) {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d try to bypass\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		//soinf->bypass(peer_addr, peer_port);
		soinf->peer_addr = peer_addr;
		soinf->peer_port = peer_port;
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	}
	//soinf->bypass();
}

extern "C"
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    const struct bsd_sockaddr *addr, socklen_t alen)
{
	int error;
	ssize_t bytes;

	sock_d("sendto(fd=%d, buf=..., len=%d, flags=0x%x, ...", fd, len, flags);
	fprintf_pos(stderr, "INFO sendto fd=%d\n", fd);

	ssize_t len2 = sendto_bypass(fd, buf, len, flags, addr, alen);
	if (len2) {
		return len2;
	}

	error = linux_sendto(fd, (caddr_t)buf, len, flags, (caddr_t)addr,
			   alen, &bytes);
	if (error) {
		sock_d("sendto() failed, errno=%d", error);
		errno = error;
		return -1;
	}


	// try to enable bypass after first sent packet
	// NO, receiver might not be up yet.
	// So, receiver should enable bypass for sender, after he gets first packet.
	// Here, just save peer addr/port - so that we get "connected" like
	sock_info *soinf = sol_find(fd);
	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		return bytes;
	}
	struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
	uint32_t peer_addr = in_addr->sin_addr.s_addr;
	ushort peer_port = in_addr->sin_port;
	fprintf_pos(stderr, "INFO fd=%d peer addr=0x%08x,port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));
	if (so_bypass_possible(soinf, soinf->my_port) ||
		so_bypass_possible(soinf, peer_port)) {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d try to bypass\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		//soinf->bypass(peer_addr, peer_port);
		soinf->peer_addr = peer_addr;
		soinf->peer_port = peer_port;
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	}
	//soinf->bypass();


	return bytes;
}

extern "C"
ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	int error;
	ssize_t bytes;

	sock_d("send(fd=%d, buf=..., len=%d, flags=0x%x)", fd, len, flags)
	fprintf_pos(stderr, "INFO send fd=%d\n", fd);

	ssize_t len2 = sendto_bypass(fd, buf, len, flags, nullptr, 0);
	if (len2) {
		return len2;
	}

	error = linux_send(fd, (caddr_t)buf, len, flags, &bytes);
	if (error) {
		sock_d("send() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return bytes;
}

extern "C"
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t bytes;
	int error;

	sock_d("sendmsg(fd=%d, msg=..., flags=0x%x)", fd, flags)
	fprintf_pos(stderr, "INFO sendmsg fd=%d\n", fd);

	/*
	buf -> iovec
	ssize_t len2 = sendto_bypass(fd, buf, len, flags, nullptr, 0);
	if (len2) {
		return len2;
	}*/

	error = linux_sendmsg(fd, (struct msghdr *)msg, flags, &bytes);
	if (error) {
		sock_d("sendmsg() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return bytes;
}

extern "C"
int getsockopt(int fd, int level, int optname, void *__restrict optval,
		socklen_t *__restrict optlen)
{
	int error;

	sock_d("getsockopt(fd=%d, level=%d, optname=%d)", fd, level, optname);

	error = linux_getsockopt(fd, level, optname, optval, optlen);
	if (error) {
		sock_d("getsockopt() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int error;

	sock_d("setsockopt(fd=%d, level=%d, optname=%d, (*(int)optval)=%d, optlen=%d)",
		fd, level, optname, *(int *)optval, optlen);

	error = linux_setsockopt(fd, level, optname, (caddr_t)optval, optlen);
	if (error) {
		sock_d("setsockopt() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int shutdown(int fd, int how)
{
	int error;

	sock_d("shutdown(fd=%d, how=%d)", fd, how);

	// Try first if it's a AF_LOCAL socket (af_local.cc), and if not
	// fall back to network sockets. TODO: do this more cleanly.
	error = shutdown_af_local(fd, how);
	if (error != ENOTSOCK) {
	    return error;
	}
	error = linux_shutdown(fd, how);
	if (error) {
		sock_d("shutdown() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int socket(int domain, int type, int protocol) /**/
{
	int s, error;

	sock_d("socket(domain=%d, type=%d, protocol=%d)", domain, type, protocol);

	error = linux_socket(domain, type, protocol, &s);
	if (error) {
		sock_d("socket() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	sol_insert(s, protocol);
	return s;
}

extern "C"
int so_bypass(int fd)
{
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return -1;
	}
	soinf->bypass();
	return 0;  
}
