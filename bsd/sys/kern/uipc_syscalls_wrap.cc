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

#if 1
#  undef fprintf_pos
#  define fprintf_pos(...) /**/
#endif

#define BYPASS_BUF_SZ (1024*1024*30)

//#define my_memcpy memcpy
#define my_memcpy memmove
//#define my_memcpy repmovsb 
// TODO TRY repmovsb 

uint32_t my_ip_addr = 0x00000000;
bool do_sbwait = true;
// all sockets
class sock_info;
std::vector<sock_info*> so_list;

inline void* my_memcpy_memcpy(void *dest, const void *src, size_t n) {
	return memcpy(dest, src, n);
}
inline void* my_memcpy_memmove(void *dest, const void *src, size_t n) {
	return memmove(dest, src, n);
}


// v host order
//#define IPV4_TO_UINT32(a,b,c,d) ( (((a&0x000000FF)*256 + (b&0x000000FF))*256 + (c&0x000000FF))*256 + (d&0x000000FF) )
#define IPV4_TO_UINT32(a,b,c,d) (ntohl( (a)*0x01000000ul + (b)*0x00010000ul + (c)*0x00000100ul + (d)*0x00000001ul ))
void ipbypass_setup() {
	fprintf_pos(stderr, "TADA...\n", "");
	//sleep(1);
	my_ip_addr = IPV4_TO_UINT32(192,168,122,90);
	so_list.reserve(10);
}

bool in_range(size_t val, size_t low, size_t high)
{
	if (high>low) {
		return low <= val && val < high;
	}
	else {
		return low <= val || val < high;
	}
}

class RingMessageHdr {
public:
	size_t length;
	// char data[1]; // variable length array
};

class RingMessage : RingMessageHdr {
public:
	char data[1]; // variable length array
public:
	char* to_buffer() {return data;}
};

class RingBuffer {
public:
	RingBuffer();
	~RingBuffer();
	void alloc(size_t len);
	size_t push(const void* buf, size_t len);
	size_t pop(void* buf, size_t len);
public:
	size_t available_read();
	size_t available_write();
	size_t push_part(const void* buf, size_t len);
	size_t pop_part(void* buf, size_t len);
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
	fprintf_pos(stderr, "RingBuffer::RingBuffer this=%p data=%p at %p \n", this, data, &data);
	length = 0;
	rpos = 0;
	wpos = 0;
	// da ne bo cakanja na malloc v prvem recvfrom. Ce je sploh problem cakanje na malloc - mogoce samo IP-layer malo steka :/
	//alloc(BYPASS_BUF_SZ);
}

RingBuffer::~RingBuffer()
{
	if (data) {
		fprintf_pos(stderr, "RingBuffer::~RingBuffer this=%p free-ing data=%p at %p \n", this, data, &data);
		free(data);
	}
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
	fprintf_pos(stderr, "RingBuffer::alloc this=%p data=%p at %p len=%d\n", this, data, &data, len);
	memset(data, 0x11, len);
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

// TODO push messages one-by-one
// limit max size - 2 kB
size_t RingBuffer::push_part(const void* buf, size_t len)
{
	size_t wpos2, len1, len2;
	assert(len <= available_write());
	if (len + sizeof(RingMessageHdr) > available_write()) {
		// drop packet
		return 0;
	}
	wpos2 = wpos + len;
	if (wpos2 <= length) {
		my_memcpy(data + wpos, buf, len);
		wpos = wpos2;
	}
	else {
		len1 = length - wpos;
		len2 = len - len1;
		my_memcpy(data + wpos, buf, len1);
		my_memcpy(data, buf + len1, len2);
		wpos = len2;
	}
	return len;
}
size_t RingBuffer::push(const void* buf, size_t len)
{
	RingMessageHdr hdr;
	while (sizeof(hdr) + len > available_write()) {
		// drop packet
		//return 0;
		fprintf_pos(stderr, "RingBuffer::push delay\n");
		//usleep(1);
	}
	hdr.length = len;
	size_t len1, len2, old_wpos;
	old_wpos = wpos;
	//fprintf(stderr, "RingBuffer::push-ing len=%d , rpos=%d, wpos=%d\n", len, rpos, wpos);
	len1 = push_part(&hdr, sizeof(hdr));
	len2 = push_part(buf, len);
	//fprintf(stderr, "RingBuffer::push-ed  len=%d , rpos=%d, wpos=%d\n", len, rpos, wpos);
	assert(len1 == sizeof(hdr));
	assert(len2 == len);
	// check stored length
	len1 = ((RingMessageHdr*)(void*)(data+old_wpos))->length;
	assert(len1 == hdr.length);
	assert(len1 == len);
	return len;
}

size_t RingBuffer::pop_part(void* buf, size_t len)
{
	size_t rpos2, len1, len2;
	assert(len <= available_read());
	assert(len <= length);
	//size_t readable_len = available_read();
	rpos2 = rpos + len;
	if (rpos2 <= length) {
		my_memcpy(buf, data + rpos, len);
		rpos = rpos2;
	}
	else {
		len1 = length - rpos;
		len2 = len - len1;
		my_memcpy(buf, data + rpos, len1);
		my_memcpy(buf + len1, data, len2);
		rpos = len2;
	}
	return len;
}

size_t RingBuffer::pop(void* buf, size_t len)
{
	RingMessageHdr hdr;
	size_t readable_len;
	/* if (sizeof(hdr) + 0 > readable_len) {
		// no packet
		return 0;
	} */
	//fprintf(stderr, "RingBuffer::pop\n");
	int cnt = 0;
	// (sizeof(hdr)+1 -> assume all mesages are at least 1 B long.
	// otehrwise, the assert(sizeof(hdr) + hdr.length <= readable_len); fails
	while ((sizeof(hdr) + 1) > (readable_len = available_read())) {
		if(cnt==0)
			fprintf_pos(stderr, "RingBuffer::pop delay cnt=%d readable_len=%d wpos=%d rpos=%d\n", cnt, (int)readable_len, wpos, rpos);
		cnt++;
		//usleep(1);
	}
		if(cnt>0)
			fprintf_pos(stderr, "RingBuffer::pop delay cnt=%d readable_len=%d wpos=%d rpos=%d\n", cnt, (int)readable_len, wpos, rpos);
	//fprintf(stderr, "RingBuffer::pop-ing len=%d , rpos=%d, wpos=%d\n", len, rpos, wpos);
	pop_part(&hdr, sizeof(hdr));
	assert(sizeof(hdr) + hdr.length <= readable_len);
	len = pop_part(buf, hdr.length);
	assert(len == hdr.length);
	//fprintf(stderr, "RingBuffer::pop-ed  len=%d , rpos=%d, wpos=%d\n", len, rpos, wpos);
	return hdr.length;
}

/*--------------------------------------------------------------------------*/

class sock_info {
public:
	sock_info();
	void bypass(uint32_t peer_addr=0xFFFFFFFF, ushort peer_port=0, int peer_fd=-1);
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
	int peer_fd; // ker je iskanje prevec fff
};

sock_info::sock_info() {
	fd = -1;
	is_bypass = false;
	my_proto = -1;
	my_addr = 0xFFFFFFFF;
	my_port = 0;
	peer_addr = 0xFFFFFFFF;
	peer_port = 0;
	peer_fd = -1;
}

void sock_info::bypass(uint32_t _peer_addr, ushort _peer_port, int _peer_fd) {
	if (!is_bypass) {
		is_bypass = true;
		peer_addr = _peer_addr;
		peer_port = _peer_port;
		peer_fd = _peer_fd;
		//in_buf.set_capacity(BYPASS_BUF_SZ); // WTF - 16 je premajhna stevilka, in crashne ????? 16kB je OK.
		ring_buf.alloc(BYPASS_BUF_SZ);
		//fprintf_pos(stderr, "INFO fd=%d, in_buf size=%d capacity=%d reserve=%d\n",
		//	fd, in_buf.size(), in_buf.capacity(), in_buf.reserve() );
		fprintf_pos(stderr, "INFO fd=%d this=%p is_bypass=%d peer fd=%d,addr=0x%08x,port=%d\n",
			fd, this, is_bypass, 
			peer_fd, ntohl(peer_addr), ntohs(peer_port));
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


void sol_insert(int fd, int protocol) {
	sock_info *soinf = new sock_info;
	fprintf(stderr, "INSERT-ing fd=%d soinf=%p\n", fd, soinf);
	soinf->fd = fd;
	soinf->my_proto = protocol;
	so_list.push_back(soinf);
	fprintf(stderr, "INSERT-ed fd=%d soinf=%p\n", fd, soinf);
}

void sol_remove(int fd, int protocol) {
	fprintf_pos(stderr, "DELETE-ing fd=%d\n", fd);
	// TODO a bi moral tudi peer-a removati?
	for (auto it = so_list.begin(); it != so_list.end(); ) {
		sock_info *soinf = *it;
		if (soinf && soinf->fd == fd) {

			//so_list.erase(it); // invalidira vse iteratorje. predvsem sam it iteratero..........
			//*it = nullptr; // fake delete
			//it = so_list.erase(it); // samo potem ne moreta dva thread parallelno iskati po listi.

			// fake delete, in se vedno crashne
			// treba se malo pavze, da ta-drugi-thread neha dostopati (iperf client neha posiljati)
			// std::shared_ptr
			sleep(1);
			*it = nullptr;
			

			fprintf_pos(stderr, "DELETE-ed fd=%d soinf=%p\n", fd, soinf);
			memset(soinf, 0x00, sizeof(*soinf));
			delete soinf;
		}
		else {
			it++;
		}
	}
}

sock_info* sol_find(int fd) {
	auto it = std::find_if(so_list.begin(), so_list.end(), 
		[&] (sock_info *soinf) { return soinf && soinf->fd == fd; } );
	if (it == so_list.end()) {
		if(fd>5) {
			fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		}
		return nullptr;
	}
	return *it;
}

sock_info* sol_find_me(int fd, uint32_t my_addr, ushort my_port) {
	auto it = std::find_if(so_list.begin(), so_list.end(), 
		[&] (sock_info *soinf) { 
			// protocol pa kar ignoriram, jejhetaja.
			return 	soinf && 
					(soinf->my_addr == INADDR_ANY || soinf->my_addr == my_addr) &&
					(soinf->my_port == my_port);
		});
	if (it == so_list.end()) {
		fprintf_pos(stderr, "ERROR fd=%d me 0x%08x:%d not found\n", fd, ntohl(my_addr), ntohs(my_port));
		return nullptr;
	}
	return *it;
}
sock_info* sol_find_peer2(int fd, uint32_t peer_addr, ushort peer_port) {
	auto it = std::find_if(so_list.begin(), so_list.end(), 
		[&] (sock_info *soinf) {
			if (!soinf)
				return false; 
			// protocol pa kar ignoriram, jejhetaja.
			int addr_match;
			//uint32_t my_iface_ip_addr = htonl( 0xc0a87a5a ); // 192.168.122.90 test VM ip :/
			addr_match = soinf->peer_addr == INADDR_ANY || 
				soinf->peer_addr == peer_addr ||
				//(peer_addr == my_iface_ip_addr) ||
				(peer_addr == INADDR_ANY); // tale pogoj bo pa napacen. ker zdaj bi 
			return addr_match && (soinf->peer_port == peer_port);
		});
	if (it == so_list.end()) {
		fprintf_pos(stderr, "ERROR fd=%d peer 0x%08x:%d not found\n", fd, ntohl(peer_addr), ntohs(peer_port));
		return nullptr;
	}
	return *it;
}
bool so_bypass_possible(sock_info* soinf, ushort port) {
	
	//return false;
	
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
	fprintf_pos(stderr, "fd=%d me %d_0x%08x:%d\n", fd, fd, ntohl(soinf->my_addr), ntohs(soinf->my_port));

	// enable bypass for all server-side sockets.
	// But not to early.
	//soinf->bypass();
	//int peer_fd = -1;
	if ( so_bypass_possible(soinf, soinf->my_port) &&
		  (soinf->my_addr == my_ip_addr ||
		   soinf->my_addr == 0x00000000 /*ANY ADDR*/ )
	   ) {
		fprintf_pos(stderr, "INFO fd=%d me %d_0x%08x:%d try to bypass\n", 
			fd, soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port));
		soinf->bypass();
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me %d_0x%08x:%d bypass not possible\n", 
			fd, soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port));
	}

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

// PA ze v bind treba bypass prizgati, ce se le da...
extern "C"
int connect(int fd, const struct bsd_sockaddr *addr, socklen_t len)
{
	int error;

	sock_d("connect(fd=%d, ...)", fd);
	fprintf_pos(stderr, "INFO connect fd=%d\n", fd);

	// if we connect to intra-host VM, use bypass
	// OR, if we connect to the same-VM, use bypass
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return -1;
	}

	/*
	client se povezuje na obstojec server
	client se povezuje na server, ki se ne tece
	server se povezuje "nazaj" na client, ki ze tece.
	*/

	struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
	uint32_t peer_addr = in_addr->sin_addr.s_addr;
	ushort peer_port = in_addr->sin_port;
	int peer_fd = -1;
	sock_info *soinf_peer = nullptr;
	//bool do_linux_connect = true;
	fprintf_pos(stderr, "INFO connect fd=%d peer addr=0x%08x,port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));
	if ( (so_bypass_possible(soinf, soinf->my_port) ||
		  so_bypass_possible(soinf, peer_port) ) &&
		  (
		  	(peer_addr == my_ip_addr) ||

		  	// real-ip-stack ni videl paketa, ki ga je client poslal serverju.
		  	// in zdaj se server ne more connect. No, med drugim je tu v *addr vse 0x00, ker 
		  	// sem malo prevec poenostavil .... 
		  	// Potem bo crknil na linux_connect, kar je ssss.
		  	// Najbrz bi bilo OK, ce bi vedel, kak s katerega IP:port bi mi client posiljal ...
		  	// zaenkrat preskocim linux_connect.
			(soinf->my_addr==0x00000000 && soinf->my_port>0) /*najbrz jaz poslusam, je peer lahko prazen, ker sem goljufal*/
		  )
	   ) {

		//do_linux_connect = false;

		// peer socket je ze odprt, ali pa tudi se ni.
		// tako da peer_fd bom nasel, ali pa tudi ne.
		// TODO
		// ce peer-a se ni, ga bom moral iskati po vsakem recvmsg ??

		//sock_info *soinf_peer = sol_find_peer2(fd, peer_addr, peer_port);
		if(peer_port != 0) {
			// to je ok za UDP clienta - ta se poveze za znani server ip/port.
			soinf_peer = sol_find_me(fd, peer_addr, peer_port);
		}
		else {
			// najbrz smo server, ki se povezuje nazaj na clienta.
			// peer of peer-a sem jaz logika
			// oz kdor ima mene za peer-a, tistega bom jaz imel za peer-a.
			soinf_peer = sol_find_peer2(fd, soinf->my_addr, soinf->my_port);
		}
		
		assert(soinf_peer != nullptr); // ali pa implementiraj se varianto "najprej client, potem server"
		
		if (soinf_peer) {
			peer_fd = soinf_peer->fd;
		}
		fprintf_pos(stderr, "INFO connect fd=%d me %d_0x%08x:%d peer %d_0x%08x:%d try to bypass\n", 
			fd, fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
			peer_fd, ntohl(peer_addr), ntohs(peer_port));
		if(soinf->is_bypass) {
			fprintf_pos(stderr, "INFO already bypass-ed fd me/peer %d %d.\n", fd, peer_fd);
			// hja, zdaj pa is_baypass je ze true, peer_* pa na defualt vrednostih . jej jej jej. 
			soinf->peer_fd = peer_fd;
			soinf->peer_addr = peer_addr;
			soinf->peer_port = peer_port;
		}
		else {
			soinf->bypass(peer_addr, peer_port, peer_fd);
		}
	}
	else {
		fprintf_pos(stderr, "INFO connect fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	}

	fprintf_pos(stderr, "INFO connect new_state fd=%d %d_0x%08x:%d <-> %d_0x%08x:%d\n", 
		fd, 
		soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
		soinf->peer_fd, ntohl(soinf->peer_addr), ntohs(soinf->peer_port));

	/* ta connect crkne, ce je to UDP server - t.j. bind, nato connect. Vmes moras vsaj en paket prejeti?
	Samo potem, ko preskocim connect, me pa zaj naslednji server socket, ko nov thread javi "bind failed: Address in use".
	 */
	if (in_addr->sin_port == 0) {
		//do_linux_connect = false;
		// server se hoce connectat-i nazaj na clienta, samo zaradi bypass ni izvedel pravega porta.
		// dodaj se eno goljufijo vec...
		fprintf(stderr, "INFO INFO INFO connect fd=%d insert faked addr/port from soinf_peer %d_0x%08x:%d\n",
			fd, soinf_peer->fd, ntohl(soinf_peer->my_addr), ntohs(soinf_peer->my_port));
		in_addr->sin_addr.s_addr = soinf_peer->my_addr;
		in_addr->sin_port = soinf_peer->my_port;
	}
	fprintf(stderr, "INFO linux_connect fd=%d to in_addr 0x%08x:%d\n",
		fd, ntohl(in_addr->sin_addr.s_addr), ntohs(in_addr->sin_port));

	error = linux_connect(fd, (void *)addr, len);
	if (error) {
		sock_d("connect() failed, errno=%d", error);
		fprintf_pos(stderr, "ERROR connect() failed, errno=%d\n", error);
		errno = error;
		//return -1;

		// no, pa dajmo probati to na tiho ignorirati :/
		// sej je samo mali iperf server problem....
		fprintf(stderr, "ERROR connect() failed, errno=%d NA TIHEM IGNORIRAM< da bo vsaj iperf server nekaj lahko vrnil. Tudi ce potem crashne...\n", error);
		return 0;
	}

	// ce se ne poznam moje addr/port
	//int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	if (soinf->my_port == 0 || soinf->my_addr == 0xFFFFFFFF || soinf->my_addr == 0x00000000) {
		struct bsd_sockaddr addr2;
		socklen_t addr2_len = sizeof(addr2);
		error = getsockname(fd, &addr2, &addr2_len);
		if (error) {
			sock_d("connect / getsockname() failed, error=%d", error);
			fprintf_pos(stderr, "ERROR connect / getsockname() failed, error=%d\n", error);
			return -1;
		}
		struct sockaddr_in* in_addr2 = (sockaddr_in*)(void*)&addr2;
		soinf->my_addr = in_addr2->sin_addr.s_addr;
		soinf->my_port = in_addr2->sin_port;
		fprintf_pos(stderr, "INFO connect soinf updated fd=%d %d_0x%08x:%d <-> %d_0x%08x:%d\n", 
			fd, 
			soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
			soinf->peer_fd, ntohl(soinf->peer_addr), ntohs(soinf->peer_port));
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
	fprintf_pos(stderr, "fd=%d BYPASS-ed\n", fd);

	// ce sem od prejsnjega branja dobil dva pakate, potem sem dvakrat nastavil flag/event za sbwait.
	// ampak sbwait() bo sedaj samo enkrat pocistil, 
	// tako da, ce podatki so, potem jih beri brez sbwait() cakanja.
if(do_sbwait) {
	if( soinf->ring_buf.available_read() <= sizeof(RingMessageHdr) ) {

	/* bsd/sys/kern/uipc_syscalls.cc:608 +- eps */
	int error;
	struct file *fp;
	struct socket *so;
	error = getsock_cap(fd, &fp, NULL);
	if (error)
		return (error);
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	SOCK_LOCK(so);  // ce dam stran: Assertion failed: SOCK_OWNED(so) (bsd/sys/kern/uipc_sockbuf.cc: sbwait_tmo: 144)
	error = sbwait(so, &so->so_rcv);
	//error = sbwait(so, &so->so_rcv); /* se obesi, oz dobim samo vsak drugi paket... */
	SOCK_UNLOCK(so);
	fdrop(fp); /* TODO PAZI !!! */
	
	}
}
else {
	while( soinf->ring_buf.available_read() <= sizeof(RingMessageHdr) ) {
	}
}
	/*
	Socket je bypass-ed. Ne smem iti recvfrom -> linux_recvfrom, ker utegne tam neskoncno dolgo viseti.
	Ali pa morda tudi kak paket pozabi (ker preveckrat kilcem sbwait()?)
	Torej bom kar probal cakati na podatke ;?>

	to mi bo morda spet zj... iperf :/
	*/
	// if (soinf->ring_buf.available_read() > sizeof(RingMessageHdr))
	{
		//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
		size_t len2;
		len2 = soinf->data_pop(buf, len);
		return len2;
	}

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

#if 0
	// try to enable bypass after first received packet
 	sock_info *soinf = sol_find(fd);
	if(!soinf) {
		return bytes;
	}
	struct sockaddr_in* in_addr = (sockaddr_in*)(void*)addr;
	uint32_t peer_addr = in_addr->sin_addr.s_addr;
	ushort peer_port = in_addr->sin_port;
	fprintf_pos(stderr, "INFO fd=%d me 0x%08x:%d, peer 0x%08x:%d\n", fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	//
	// and enable for peer too.
	// But peer didn't save its port and addr :/
	// So I should search fore someone who has me as peer ?? mess mess mess
 	sock_info *peer_soinf = nullptr;
 	//peer_soinf = sol_find_peer2(fd, peer_addr, peer_port);
 	peer_soinf = sol_find_peer2(fd, soinf->my_addr, soinf->my_port); // search for socket, which is sending to me.
	fprintf_pos(stderr, "INFO fd=%d peer_soinf=%p %d_0x%08x:%d \n", fd, peer_soinf, peer_soinf->fd, ntohl(peer_addr), ntohs(peer_port));

 	//
	if(!peer_soinf) {
		return bytes; //TODO_tole?
	}
	bool bypass_possible_me, bypass_possible_peer; 
	bypass_possible_me = so_bypass_possible(nullptr, soinf->my_port);
	bypass_possible_peer = so_bypass_possible(nullptr, peer_port);
	fprintf_pos(stderr, "INFO fd=%d bypass_possible me %d, peer %d\n", fd, bypass_possible_me, bypass_possible_peer);
	if (bypass_possible_me || bypass_possible_peer) {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d try to bypass\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		soinf->bypass(peer_addr, peer_port, peer_soinf->fd);
		//peer_soinf->bypass(peer_addr, peer_port);
		peer_soinf->bypass(0x00000000, soinf->my_port, fd); // ANY addr, ali pa -1, ali pa kar peer_addr, saj je enak - ista VM
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
	}
#endif
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

	//return len;

	int error;
 	sock_info *soinf = sol_find(fd);
	fprintf_pos(stderr, "fd=%d soinf=%p %d\n", fd, soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		return 0;
	}

	// no, zdaj pa bom morda bypass omogocil ob prvem poslanem paketu
	/*
	if (!soinf->is_bypass) {
		return 0;
	}*/

	uint32_t peer_addr = 0xFFFFFFFF;
	ushort peer_port = 0;
	int peer_fd = -1;
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

	fprintf_pos(stderr, "fd=%d peer_addr=0x%08x peer_port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));



	// isto kot v connect - samo ce imas sendto, potem lahko connect preskocis ...
	fprintf_pos(stderr, "INFO fd=%d me %d_0x%08x:%d, peer addr=0x%08x,port=%d\n", fd, 
		soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
		ntohl(peer_addr), ntohs(peer_port));
	/*int aa,bb,cc;
	aa = so_bypass_possible(soinf, soinf->my_port);
	bb = so_bypass_possible(soinf, peer_port);
	cc = peer_addr == my_ip_addr;
	fprintf_pos(stderr, "DBG abc %d %d %d\n", aa, bb, cc); */
	sock_info *soinf_peer = nullptr;
	if(soinf->is_bypass) {
		soinf_peer = sol_find_me(fd, peer_addr, peer_port);
		if(!soinf_peer) {
			fprintf_pos(stderr, "ERROR no valid peer found me/peer %d %d, soinf_peer=%p.\n", fd, peer_fd, soinf_peer);
			return 0;
		}
		peer_fd = soinf_peer->fd;
	}
	else {
	if ( (so_bypass_possible(soinf, soinf->my_port) ||
		  so_bypass_possible(soinf, peer_port) ) &&
		  (peer_addr == my_ip_addr)
	   ) {
		// peer socket je ze odprt, ali pa tudi se ni.
		// tako da peer_fd bom nasel, ali pa tudi ne.
		// TODO
		// ce peer-a se ni, ga bom moral iskati po vsakem recvmsg ??
		//soinf_peer = sol_find_peer2(fd, peer_addr, peer_port);
		// No, dajmo iskati vse 'moje' sockete, ki poslusajo na peer_port.
		// Na njih posiljam, oni so moj peer.
		soinf_peer = sol_find_me(fd, peer_addr, peer_port);

		// assert(soinf_peer != nullptr); // ali pa implementiraj se varianto "najprej client, potem server"
		if (soinf_peer) {
			peer_fd = soinf_peer->fd;
		}
		else {
			// peer_fd je se vedno -1, in ne morem poslati.
			// se zgodi, ko iperf server zapre svoj port, in client se vedno probova poslati
			fprintf_pos(stderr, "ERROR no valid peer found me/peer %d %d, soinf_peer=%p.\n", fd, peer_fd, soinf_peer);
			return 0;
		}
		fprintf_pos(stderr, "INFO fd=%d me %d_0x%08x:%d peer %d_0x%08x:%d try to bypass\n", 
			fd, fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
			peer_fd, ntohl(peer_addr), ntohs(peer_port));
		if(soinf->is_bypass) {
			fprintf_pos(stderr, "INFO already bypass-ed fd me/peer %d %d.\n", fd, peer_fd);
		}
		else {
			soinf->bypass(peer_addr, peer_port, peer_fd);
		}
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me=0x%08x:%d peer 0x%08x:%d bypass not possible\n", 
			fd, ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		return 0;
	}
	}






	fprintf_pos(stderr, "fd=%d BYPASS-ed\n", fd);
	// zdaj pa najdi enga, ki temu ustreza
	// CEL JEBENI ROUTING BI MORAL EVALUIRATI !!!!! fuck.
	// Pa - a naj gledam IP addr ali MAC addr ?
 	
 	//sock_info *soinf_peer = sol_find_me(fd, peer_addr, peer_port);
 	////////sock_info *soinf_peer = sol_find(soinf->peer_fd);
 	
 	// Ok, peer je server, ki nam odgovori via sendto. Potem je lahko soinf_peer->peer_fd == -1, in != fd.
 	// Sele po (morebitnem!) connect() se soinf_peer->peer_fd nastavi na znan fd.
 	// Tako da tu tega se ne morem preveriti. 
 	//assert(soinf_peer->peer_fd == fd);

	// ta bi pa moral drzati. vsaj za client stran.
	// ali pa, vsaj en od obeh bi moral drzati. Vsaj nekdo mora vedetik, kam hoce posiljati :).
	// razen, morda, ce vsi pocnejo samo sendto.
	// Meh, iperf client - tu zavpije
 	//assert(soinf_peer->fd == soinf->peer_fd);

	fprintf_pos(stderr, "fd=%d me %d_0x%08x:%d peer %d_0x%08x:%d\n", fd,
		soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
		soinf_peer->fd, ntohl(soinf_peer->my_addr), ntohs(soinf_peer->my_port));

	assert(soinf_peer->is_bypass);
	assert(soinf_peer->ring_buf.data);
	size_t len2=0;
	len2 = soinf_peer->data_push(buf, len);

if (do_sbwait) {
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
}
else {
	return len2;
}

	/*
	iz sbwait_tmo()
	sched::thread::wait_for(SOCK_MTX_REF(so), *so->so_nc, sb->sb_cc_wq, tmr, sc);
	so->so_nc_busy = false;
	so->so_nc_wq.wake_all(SOCK_MTX_REF(so));
	*/
}

/*
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
}*/

extern "C"
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    const struct bsd_sockaddr *addr, socklen_t alen)
{
	int error;
	ssize_t bytes;

	sock_d("sendto(fd=%d, buf=..., len=%d, flags=0x%x, ...", fd, len, flags);
	fprintf_pos(stderr, "INFO sendto fd=%d len=%d\n", fd, len);

	ssize_t len2 = sendto_bypass(fd, buf, len, flags, addr, alen);
	if (len2) {
		// a ce vsaj en paket posljme, bo potem lahko server se en connect naredil ?? Please please please...
		error = linux_sendto(fd, (caddr_t)buf, len, flags, (caddr_t)addr,
				   alen, &bytes);

		return len2;
	}

	error = linux_sendto(fd, (caddr_t)buf, len, flags, (caddr_t)addr,
			   alen, &bytes);
	if (error) {
		sock_d("sendto() failed, errno=%d", error);
		errno = error;
		return -1;
	}

#if 0
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

	// soft of implicit connect - like we will always sendto to same peer.
	soinf->peer_addr = peer_addr;
	soinf->peer_port = peer_port;
	/*
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
	}*/
	//soinf->bypass();
#endif

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
	fprintf_pos(stderr, "fd=%d\n", fd);

    sol_remove(fd, -1);

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

/*extern "C"
int so_bypass(int fd)
{
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return -1;
	}
	soinf->bypass();
	return 0;  
}*/
