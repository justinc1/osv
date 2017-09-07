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
#include <osv/poll.h> // int poll_wake(struct file* fp, int events);


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


#include <osv/ipbypass.h>

TIMED_TRACEPOINT(trace_ipby_accept, "tid=%d fd=%d, fd2=%d", long, int, int);
TIMED_TRACEPOINT(trace_ipby_connect, "tid=%d fd=%d", long, int);
TIMED_TRACEPOINT(trace_ipby_recvfrom_bypass, "tid=%d fd=%d", long, int);
//      TRACEPOINT(trace_ipby_recvfrom_bypass_info, "tid=%d fd=%d LINE=%d msg=%s", long, int, int, const char*);
TIMED_TRACEPOINT(trace_ipby_sendto_bypass, "tid=%d fd=%d", long, int);
//TIMED_TRACEPOINT(trace_ipby_test, "tid=%d fd=%d", long, int);


#if 1
#  undef fprintf_pos
#  define fprintf_pos(...) /**/
#  define SENDTO_BYPASS_USLEEP(x)
#else
#  define SENDTO_BYPASS_USLEEP(x) usleep(x)
#endif
#if 0
#  undef assert
#  define assert(...) /**/
#endif

#include <osv/mutex.h>
#include <osv/ring_buffer_v0.hh>
//#define RingBuffer RingBufferV0
#define RingBuffer RingBuffer_atomic

#define IPBYPASS_ENABLED 1
#define IPBYPASS_LOCKED 0
#define MEM_BARRIER 
	//asm volatile("" ::: "memory")

#if IPBYPASS_LOCKED
static mutex mtx_ipbypass;
#endif

pid_t ipbypass_tid0 = 1000000;

uint32_t my_ip_addr = 0x00000000;
uint32_t my_owner_id = 0;
// all sockets
class sock_info;
typedef sock_info* so_list_t[SOCK_INFO_LIST_LEN];
so_list_t* so_list = nullptr;

inline void* my_memcpy_memcpy(void *dest, const void *src, size_t n) {
	return memcpy(dest, src, n);
}
inline void* my_memcpy_memmove(void *dest, const void *src, size_t n) {
	return memmove(dest, src, n);
}

//extern "C" int socket(int domain, int type, int protocol);
int (*socket_func)(int, int, int) = nullptr;

// return true if SBS_CANTRCVMORE in so->so_rcv.sb_state is set
// use in poll-for-data loop to exit without data, when socet get closed while we are already waiting for data.
bool check_sock_flags(int fd) {
	int error;
	bool cant_recv = false;
	struct file *fp;
	struct socket *so;
	error = getsock_cap(fd, &fp, NULL);
	if (error)
		return (error);
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	SOCK_LOCK(so);
	//
	cant_recv = so->so_rcv.sb_state & SBS_CANTRCVMORE;
	//
	SOCK_UNLOCK(so);
	fdrop(fp); /* TODO PAZI !!! */
	return cant_recv;
}


/*--------------------------------------------------------------------------*/

void mybreak() {
}

// addr is in network byte order
uint32_t ipv4_addr_to_id(uint32_t addr) {
	return ntohl(addr) & 0xFF;
}

class sock_info {
public:
	sock_info();
	//void bypass(uint32_t peer_addr=0xFFFFFFFF, ushort peer_port=0, int peer_fd=-1);
	void bypass(uint32_t peer_id, uint32_t peer_addr, ushort peer_port, int peer_fd);
	size_t data_push(const void* buf, size_t len);
	size_t data_pop(void* buf, size_t len /*, short *so_rcv_state=nullptr*/);
	void unsafe_remove();
	static int unsafe_remove_all_my();
public:
    void call_ctor();
    void call_dtor();
    static sock_info* alloc_ivshmem();
    void free_ivshmem();
    const char* c_str();
public:
	short flags; // my state etc
	uint32_t my_id; // VM owner id
	int fd;
	bool is_bypass;
    std::atomic<bool> modified;
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
	uint32_t peer_id;
	uint32_t peer_addr;
	ushort peer_port;
	int peer_fd; // ker je iskanje prevec fff

	// accept_soinf->fd is fd returned by accept. the descriptor fd is allocated by accepting peer,
	// peer_* values are set by connecting peer.
	sock_info *accept_soinf;
	sock_info *connecting_soinf;
	sock_info *listen_soinf;
	bool is_accepted;
	uint64_t scan_mod, scan_old;
};

sock_info::sock_info() {
	call_ctor();
}

void sock_info::call_ctor() {
	ring_buf.call_ctor();
	flags = 0;
	my_id = 0;
	peer_id = 0;
	fd = -1;
	is_bypass = false;
	modified = false;
	my_proto = -1;
	my_addr = 0xFFFFFFFF;
	my_port = 0;
	peer_addr = 0xFFFFFFFF;
	peer_port = 0;
	peer_fd = -1;
	accept_soinf = nullptr;
	connecting_soinf = nullptr;
	listen_soinf = nullptr;
	is_accepted = false;

	scan_mod = scan_old = 0;
}

void sock_info::unsafe_remove() {
	// Just reset all memory to 0x00
	// After VM reboot, the ivshmem based memory should appear clean.
	// c_str is safe to call - it uses only this->xx data, not this->xx->yy.
	fprintf_pos(stderr, "UNSAFE DELETE-ing vm_id=%d, soinf=%p %s\n", my_owner_id, this, c_str());
	memset(this, 0x00, sizeof(*this));
}

const char* sock_info::c_str() {
	static __thread char desc[1024]="";
	// gcc6 will optimize away "if this != NULL" - use strcmp
	char tmp[100];
	snprintf(tmp, sizeof(tmp), "%d", (intptr_t)this);
	if (0==strcmp(tmp, "0") /* this == NULL */) {
		snprintf(desc, sizeof(desc), "(nullptr)");
	}
	else {
		snprintf(desc, sizeof(desc), "%d:%d_0x%08x:%d<-->%d:%d_0x%08x:%d",
			my_id, fd, ntohl(my_addr), ntohs(my_port),
			peer_id, peer_fd, ntohl(peer_addr), ntohs(peer_port)
			);
	}
	return desc;
}

void sock_info::call_dtor() {
}

sock_info* sock_info::alloc_ivshmem() {
    sock_info *obj;
    int shmid = ivshmem_get(sizeof(sock_info));
    if (shmid == -1) {
        return nullptr;
    }
    obj = (sock_info*)ivshmem_at(shmid);
    if (obj == nullptr) {
        return nullptr;
    }
    obj->call_ctor();
    return obj;
}

void sock_info::free_ivshmem() {
    call_dtor();
    ivshmem_dt(this);
}

void sock_info::bypass(uint32_t _peer_id, uint32_t _peer_addr, ushort _peer_port, int _peer_fd) {
	if (!is_bypass) {
		is_bypass = true;
		peer_id = _peer_id;
		peer_addr = _peer_addr;
		peer_port = _peer_port;
		peer_fd = _peer_fd;
		//in_buf.set_capacity(BYPASS_BUF_SZ); // WTF - 16 je premajhna stevilka, in crashne ????? 16kB je OK.
		ring_buf.alloc(BYPASS_BUF_SZ);
		//fprintf_pos(stderr, "INFO fd=%d, in_buf size=%d capacity=%d reserve=%d\n",
		//	fd, in_buf.size(), in_buf.capacity(), in_buf.reserve() );
		fprintf_pos(stderr, "INFO fd=%d this=%p is_bypass=%d peer id=%d,fd=%d,addr=0x%08x,port=%d\n",
			fd, this, is_bypass, 
			peer_id, peer_fd, ntohl(peer_addr), ntohs(peer_port));
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
#if IPBYPASS_LOCKED
	SCOPE_LOCK(mtx_ipbypass);
#endif
	return ring_buf.push(buf, len);
}

size_t sock_info::data_pop(void* buf, size_t len/*, short *so_rcv_state*/) {
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
#if IPBYPASS_LOCKED
	SCOPE_LOCK(mtx_ipbypass);
#endif
	return ring_buf.pop(buf, len, &flags);
}

#define dump_solist(msg) if(1) { \
	fprintf(stderr, "DBG tid=% 5d %s:%d %s: DUMP_SOLIST start: %s\n", gettid(), __FILE__, __LINE__, __FUNCTION__, msg); \
	dump_solist_func(); \
	fprintf(stderr, "DBG tid=% 5d %s:%d %s: DUMP_SOLIST stop\n", gettid(), __FILE__, __LINE__, __FUNCTION__); \
	}

void dump_solist_func() {
	sock_info *soinf;
	int ii;
	for (ii = 0; so_list && ii < SOCK_INFO_LIST_LEN; ii++) {
		soinf = (*so_list)[ii];
		if (soinf  == nullptr) {
			continue;
		}
		fflush(stderr);
		fprintf(stderr, "    tid=% 5d so_list[%d]=%p soinf=%s\n", gettid(), ii, soinf, soinf->c_str());
		fflush(stderr);
	}
}


sock_info* sol_insert(int fd, int protocol) {
	sock_info *soinf = sock_info::alloc_ivshmem();
	fprintf(stderr, "INSERT-ing fd=%d soinf=%p\n", fd, soinf);
	if (soinf == nullptr)
		return nullptr;
	soinf->my_id = my_owner_id; // tu je vedno moj VM id
	soinf->fd = fd;
	soinf->my_proto = protocol;
	int ii;
	for (ii = 0; so_list && ii < SOCK_INFO_LIST_LEN; ii++) {
		fprintf(stderr, "INSERT-search so_list[%d]=%p soinf=%s\n", ii, (*so_list)[ii], (*so_list)[ii]->c_str());
		if ((*so_list)[ii] == nullptr) {
			(*so_list)[ii] = soinf;
			fprintf(stderr, "INSERT-ed     so_list[%d]=%p soinf=%s\n", ii, (*so_list)[ii], (*so_list)[ii]->c_str());
			break;
		}
	}
	if (ii == SOCK_INFO_LIST_LEN) {
		fprintf(stderr, "ERROR sol_insert inserting fd=%d soinf=%p, all slots used :/\n", fd, soinf);
		exit(1);
	}
	return soinf;
}

// Ta naj samo oznaci soinf kot deleted.
// Ker tudi ce je socket zaprt, se vedno lahko fd uporabi v read/write().
void sol_remove(int fd, int protocol) {
	fprintf_pos(stderr, "DELETE-MARK-ing fd=%d\n", fd);
	int ii;
	for (ii = 0; so_list && ii < SOCK_INFO_LIST_LEN; ii++) {
		sock_info *soinf = (*so_list)[ii];
		if (soinf && soinf->my_id == my_owner_id && soinf->fd == fd) {
			(*so_list)[ii] = nullptr;
			fprintf_pos(stderr, "DELETE-MARK-ed fd=%d soinf=%p at ii=%d\n", fd, soinf, ii);
			//soinf->free_ivshmem();
			soinf->flags |= SOR_DELETED; // fd je neveljaven, in bo morda reused.
		}
	}
}

int sol_print(int fd);

/*
Tega lahko klicem iz mesta, kjer se free fd allocira.
*/
void sol_remove_real(int fd, int protocol) {
	fprintf_pos(stderr, "DELETE-REAL-ing fd=%d\n", fd);
	//return;
	//sleep(10);
	// TODO a bi moral tudi peer-a removati?
	// Oz, kako naj peer-u povem, da naj pocisti?? En GC-like thread, ki remove unreachable?
	int ii;
	for (ii = 0; so_list && ii < SOCK_INFO_LIST_LEN; ii++) {
		sock_info *soinf = (*so_list)[ii];
		// TODO - check VM owner_id
		if (soinf && soinf->my_id == my_owner_id && soinf->fd == fd) {

			//so_list.erase(it); // invalidira vse iteratorje. predvsem sam it iteratero..........
			//*it = nullptr; // fake delete
			//it = so_list.erase(it); // samo potem ne moreta dva thread parallelno iskati po listi.

			// fake delete, in se vedno crashne
			// treba se malo pavze, da ta-drugi-thread neha dostopati (iperf client neha posiljati)
			// std::shared_ptr
			sleep(0);
			(*so_list)[ii] = nullptr;
			

			sol_print(fd);
			fprintf_pos(stderr, "DELETE-REAL-ed fd=%d soinf=%p at ii=%d\n", fd, soinf, ii);
			memset(soinf, 0x00, sizeof(*soinf));
			soinf->free_ivshmem();
		}
		else {
			//it++;
		}
	}
}

int sock_info::unsafe_remove_all_my() {
	fprintf_pos(stderr, "UNSAFE DELETE-ing all sock_info, vm_id=%d START\n", my_owner_id);
	int ii;
	int ret = 0;
	for (ii = 0; so_list && ii < SOCK_INFO_LIST_LEN; ii++) {
		sock_info *soinf = (*so_list)[ii];
		if (soinf && soinf->my_id == my_owner_id) {
			soinf->unsafe_remove();
			ret++;
		}
		(*so_list)[ii] = nullptr;
	}
	fprintf_pos(stderr, "UNSAFE DELETE-ing all sock_info, vm_id=%d DONE\n", my_owner_id);
	return ret;
}

sock_info* sol_find(int fd) {
//	auto it = std::find_if(so_list.begin(), so_list.end(),
	if (so_list == nullptr)
		return nullptr;
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
		[&] (sock_info *soinf) { return soinf && soinf->my_id == my_owner_id && soinf->fd == fd; } );
//	if (it == so_list.end()) {
	if (it == std::end(*so_list)) {
		if(fd>5) {
			//fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		}
		return nullptr;
	}
	return *it;
}

sock_info* XXX_sol_find_me(int fd, uint32_t my_addr, ushort my_port) {
	if (so_list == nullptr)
		return nullptr;
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
		[&] (sock_info *soinf) { 
			// protocol pa kar ignoriram, jejhetaja.
			return 	soinf && 
					(soinf->my_id == my_owner_id) &&
					(soinf->my_addr == INADDR_ANY || soinf->my_addr == my_addr) &&
					(soinf->my_port == my_port);
		});
	if (it == std::end(*so_list)) {
		fprintf_pos(stderr, "ERROR fd=%d me 0x%08x:%d not found\n", fd, ntohl(my_addr), ntohs(my_port));
		return nullptr;
	}
	return *it;
}

/*
Isci peer-a, ki poslusa na podanem addr:port.
stara varianta
*/
sock_info* sol_find_peer(int fd, uint32_t peer_addr, ushort peer_port, bool allow_inaddr_any) {
	if (so_list == nullptr)
		return nullptr;
	uint32_t peer_id = ipv4_addr_to_id(peer_addr);
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
		[&] (sock_info *soinf) {
			// protocol pa kar ignoriram, jejhetaja.
			if (soinf == nullptr)
				return false;
			bool is_addr_ok;
			if (allow_inaddr_any) {
				is_addr_ok = soinf->my_addr == peer_addr || soinf->my_addr == INADDR_ANY;
			}
			else {
				is_addr_ok = soinf->my_addr == peer_addr;
			}
			return 	soinf &&
					(soinf->my_id == peer_id) &&
					is_addr_ok &&
					(soinf->my_port == peer_port);
		});
	if (it == std::end(*so_list)) {
		fprintf_pos(stderr, "ERROR fd=%d peer %d:??_0x%08x:%d not found\n", fd, peer_id, ntohl(peer_addr), ntohs(peer_port));
		return nullptr;
	}
	return *it;
}

/*
Isci peer-a, ki poslusa na podanem addr:port.
*/
sock_info* sol_find_peer_listening(int fd, uint32_t peer_addr, ushort peer_port) {
	if (so_list == nullptr)
		return nullptr;
	uint32_t peer_id = ipv4_addr_to_id(peer_addr);
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
		[&] (sock_info *soinf) {
			// protocol pa kar ignoriram, jejhetaja.
			if (soinf == nullptr)
				return false;
			bool is_addr_ok;
			is_addr_ok = soinf->my_addr == peer_addr || soinf->my_addr == INADDR_ANY;
			return 	soinf &&
					(soinf->my_id == peer_id) &&
					is_addr_ok &&
					(soinf->my_port == peer_port) &&
					(soinf->peer_id == 0) &&
					(soinf->peer_fd == -1) &&
					(soinf->peer_addr == 0xFFFFFFFF) &&
					(soinf->peer_port == 0);
		});
	if (it == std::end(*so_list)) {
		fprintf_pos(stderr, "ERROR fd=%d peer %d:??_0x%08x:%d not found\n", fd, peer_id, ntohl(peer_addr), ntohs(peer_port));
		return nullptr;
	}
	return *it;
}

/*
Isci soinf, ki ustreza kriterijem.
Npr peer-a, ki je povezan z mano, na podanem fd:addr:port.
Pol input param je odvec za iskanje, ampak jih pa lahko preverim (peer fd bi moral biti cisto dovolj).
Razsiritev: fd==-1 pomeni poljuben fd.
*/
sock_info* sol_find_full(int fd, uint32_t my_addr, ushort my_port,
	int peer_fd, uint32_t peer_addr, ushort peer_port) {
	if (so_list == nullptr)
		return nullptr;
	uint32_t my_id = ipv4_addr_to_id(my_addr);
	uint32_t peer_id = ipv4_addr_to_id(peer_addr);
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
		[&] (sock_info *soinf) {
			// protocol pa kar ignoriram, jejhetaja.
			return 	soinf &&
					(soinf->my_id == my_id) &&
					(soinf->fd == fd || -1 == fd) &&
					(soinf->my_addr == my_addr) &&
					(soinf->my_port == my_port) &&
					(soinf->peer_id == peer_id) &&
					(soinf->peer_fd == peer_fd || -1 == peer_fd) &&
					(soinf->peer_addr == peer_addr) &&
					(soinf->peer_port == peer_port);
		});
	if (it == std::end(*so_list)) {
		fprintf_pos(stderr, "ERROR fd=%d peer %d:??_0x%08x:%d not found\n", fd, peer_id, ntohl(peer_addr), ntohs(peer_port));
		return nullptr;
	}
	return *it;
}


sock_info* sol_find_peer2(int fd, uint32_t peer_addr, ushort peer_port) {
	if (so_list == nullptr)
		return nullptr;
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
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
	if (it == std::end(*so_list)) {
		fprintf_pos(stderr, "ERROR fd=%d peer 0x%08x:%d not found\n", fd, ntohl(peer_addr), ntohs(peer_port));
		return nullptr;
	}
	return *it;
}

/*
fd - listening fd.
returned sock_info - tisti fd2, ki ga bo vrnil accept.
*/
sock_info* sol_find_to_be_accepted(int fd) {
	if (so_list == nullptr)
		return nullptr;
	sock_info* soinf_listen = sol_find(fd);
	assert(soinf_listen);
	auto it = std::find_if(std::begin(*so_list), std::end(*so_list),
		[&] (sock_info *soinf) {
			if (!soinf)
				return false;
			return soinf->is_accepted == false && soinf->listen_soinf == soinf_listen;
		});
	if (it == std::end(*so_list)) {
		//fprintf_pos(stderr, "INFO fd=%d nothing to accept\n", fd);
		return nullptr;
	}
	return *it;
}

bool so_bypass_possible(sock_info* soinf, ushort port) {
#if IPBYPASS_ENABLED == 0
	return false;
#endif

	bool do_bypass=false;
	// instead of searching for intra-host VMs, use bypass for magic port numbers only
	// iperf - port 5001
	// udprecv/udpsend - port 3333
	ushort pp;
	pp = htons(port);
	if ((3330 <= pp && pp <= 3340) || 
		(5000 <= pp && pp <= 5010) || // 5000 - iperf
		(12860 <= pp && pp <= 12870) ) { // 16865 - netperf
		do_bypass = true;
	}
	pid_t tid = gettid();
	if (ipbypass_tid0 <= tid && tid <= 300) {
		// Briga me, na katerm port-u je. Samo da je dovolj visok TID,
		// potem je to moj app - netserver oz netperf :/
		// Naprej je bil netserver (oz prva via rest pognana app) na 248.
		// Potem pa kar naenkrar na 216. Nic kar naenkrat - odvisno je od stevila CPUjev, pognal sem z -c2 :/
		do_bypass = true;
	}

	// blacklist port 8000 - REST api
	if (port == htons(8000)) {
		do_bypass = false;
		soinf->is_bypass = false;
		fprintf(stderr, "DO NOT BYPASS PORT 8000, soinf=%p %s\n", soinf, soinf->c_str());
		fprintf_pos(stderr, "DO NOT BYPASS PORT 8000, soinf=%p %s\n", soinf, soinf->c_str());
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

bool soi_is_readable(int fd) {
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr)
		return false;

	size_t nbytes = soinf->ring_buf.available_read();
	if (nbytes > 0)
		return true;
	// nekdo izvaja connect, in je nastavil  soinf->accept_soinf->peer_fd
	if (soinf->accept_soinf && soinf->accept_soinf->peer_fd > -1)
		return true;

	// pa tisti, ki klice accept, obvisi, in bi ga kao treba zbuditi.
	// naj be socket v accept kar vedno readable, pa je..
	// to je bilo za netperf ali iperf ali openmpi
	// dam stran za redis
	//if (soinf->accept_soinf)
	//	return true;

	// someone is trying to connect to us
	if (soinf->connecting_soinf)
		return true;

	// Poglej, ce je kaksen socket, ki je na koncu syn syn-ack ack.
	// Za server to pomeni, da je ze dobil ack.
	// Ce ima ta novi socket isti port kot moj fd, potem ga je sprejel moj fd.
	sock_info* soinf2 = sol_find_to_be_accepted(fd);
	if (soinf2) {
		return true;
	}

	return false;
}

bool soi_is_writable(int fd) {
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr)
		return false;

	size_t nbytes = soinf->ring_buf.available_write();
	if (nbytes > 0)
		return true;

	return false;
}

bool soi_is_bypassed(sock_info* soinf) {
	if (!soinf)
		return false;
	return soinf->is_bypass;
}

int soi_ioctl(int fd, u_long cmd, void *data) {
	if(fd <= 2) return 0;

	//fprintf_pos(stderr, "fd=%d soinf=%p %d\n", fd, soinf, soinf?soinf->fd:-1);
	//fprintf(stderr, "soi_ioctl fd=%d cmd=%d\n", fd, cmd);
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr)
		return 0;

	switch(cmd) {
		case FIONBIO:
			if (data==nullptr) {
				errno = EINVAL;
				return -1;
			}
			bool enable;
			enable  = *(int*)(data);
			if (enable) {
				soinf->flags |= SOR_NONBLOCK;
			}
			else {
				soinf->flags &= ~SOR_NONBLOCK;
			}
			fprintf(stderr, "soi_ioctl fd=%d cmd=%d=FIONBIO, enable=%d, flags=0x%04x\n", fd, cmd, enable, soinf->flags);
			break;
		default:
			break;
		}
	return 0;
}

bool fd_is_bypassed(int fd) {
	sock_info *soinf = sol_find(fd);
	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	if (soinf==NULL)
		return false;
	return soinf->is_bypass;
}

//iperf crkne , ker select javi timeout :/   ??
//glej Client.cpp Client::write_UDP_FIN

/*
Server je prejel valid SYN na listen socket.
Allociraj sock_info za ta novi connection.
my in peer fd se ne bosta nastavljena,
*/
int ipby_server_alloc_sockinfo(int listen_fd,
	uint32_t my_addr, ushort my_port,
	uint32_t peer_addr, ushort peer_port)
{
	mydebug("listen_fd=%d me:?_0x%08x:%d <- peer:?_0x%08x:%d\n",
		listen_fd,
		ntohl(my_addr), ntohs(my_port),
		ntohl(peer_addr), ntohs(peer_port));
	sock_info* listen_soinf = sol_find_peer_listening(-1, my_addr, my_port);
	if (listen_soinf == nullptr)
		return 0; // bypass disabled for this socket
	sock_info* soinf = sol_insert(-1, 0);
	if (soinf == nullptr)
		return 0; // bypass disabled?
	assert(listen_fd == listen_soinf->fd);
	soinf->listen_soinf = listen_soinf;
	mydebug("link soinf=%p soinf->listen_soinf=%p\n", soinf, soinf->listen_soinf);
	soinf->bypass(0, -1/*addr*/, 0, -1/*peer_fd*/);
	//soinf.fd in peer_fd ostaneta -1;
	assert(my_owner_id == ipv4_addr_to_id(my_addr));
	soinf->my_id = my_owner_id;
	soinf->my_addr = my_addr;
	soinf->my_port = my_port;
	soinf->peer_fd = -1;
	soinf->peer_id = ipv4_addr_to_id(peer_addr);
	soinf->peer_addr = peer_addr;
	soinf->peer_port = peer_port;
	soinf->is_accepted = false;
	// ok, zdaj bo client lahko nasel ta soinf, takrat ko prejme serverjev syn-ack
	return 0;
}

/*
Server user-mode thread izvaja accept().
Ampak to ni dovolj zgodaj.
Socket/fd mora biti readable, da ga epoll opazi, sele nato se bo accept nad njim klical.
Mi je vsaj jasno, zakaj se accept sploh ne klice.
  TODO kaj ce bi se so ptr notri shranil, ali pa direktno nad njim nastavil readable flag?
  Oz nad listen fd-jem bi moral nastaviti, da je readable, da bi se potem accept klical, enkrat kasneje.
*/
int ipby_server_connect_sockinfo(int fd,
	uint32_t my_addr, ushort my_port,
	uint32_t peer_addr, ushort peer_port)
{
	mydebug("fd=%d me:?_0x%08x:%d <- peer:?_0x%08x:%d\n",
		fd,
		ntohl(my_addr), ntohs(my_port),
		ntohl(peer_addr), ntohs(peer_port));
//DBG tid=  248 bsd/sys/kern/uipc_syscalls_wrap.cc:730 ipby_server_connect_sockinfo: fd=8 me:?_0xffffffff:65535 <- peer:?_0xc0a87a5a:17988
//	sock_info* listen_soinf = NULL;// itak so vsi my_ param -1, ker jih klicatelj ne ve :/ //sol_find_peer_listening(-1, my_addr, my_port);
	sock_info* soinf;
	sock_info* soinf_peer;
	//soinf = sol_find_full(-1, my_addr, my_port, -1, peer_addr, peer_port);
	soinf_peer = sol_find_peer(-1, peer_addr, peer_port, false/*allow addr_any*/); // cmp my_ a
	soinf = sol_find_peer2(-1, peer_addr, peer_port); // cmp peer_ attr
	mydebug("fd=%d me:?_0x%08x:%d <- peer:?_0x%08x:%d; found my soinf=%p, soinf_peer=%p\n",
		fd,
		ntohl(my_addr), ntohs(my_port),
		ntohl(peer_addr), ntohs(peer_port),
		soinf, soinf_peer);
	if (soinf) {
		assert(soinf->fd == -1);
		soinf->fd = fd;

		// ne . je prezgodaj.
		//mydebug("fd=%d set is_accepted=true\n");
		//soinf->is_accepted = true;
		assert(soinf->listen_soinf != nullptr);
		assert(soinf->my_port == soinf->listen_soinf->my_port);
	}
	if (soinf_peer) {
		assert(soinf_peer->peer_fd == -1);
		soinf_peer->peer_fd = fd;
	}

	// mydebug("link soinf=%p soinf->listen_soinf=%p listen_soinf=%p\n", soinf, soinf->listen_soinf, listen_soinf);
	return 0;
}

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
#if IPBYPASS_ENABLED
	if (fd_is_bypassed(sockfd)) {
		int fd = sockfd;
		sock_info *soinf = sol_find(fd);
		fprintf_pos(stderr, "fd=%d soinf=%p %d\n", fd, soinf, soinf?soinf->fd:-1);
		if(!soinf) {
			return 0;
		}

		struct sockaddr_in* in_addr;
		in_addr = (sockaddr_in*)(void*)addr;
		if (addrlen == nullptr || *addrlen < sizeof(struct sockaddr_in)) {
			errno = EINVAL;
			return -1;
		}
		/*
		ker sem videl cisto garbage sa_family v
		btl_tcp_proc.c, mca_btl_tcp_proc_accept()
		"if( btl_endpoint->endpoint_addr->addr_family != addr->sa_family ) {"

		bsd_sockaddr vsebuje char sa_len, char sa_family, sa_data
		linux addr je pa brez tistega len na zacetku, in namesto char sa_family je short sin_family
		*/
		in_addr->sin_family = AF_INET;
		in_addr->sin_addr.s_addr = soinf->my_addr;
		in_addr->sin_port = soinf->my_port;

		return 0;
	}
#endif

	error = linux_getsockname(sockfd, addr, addrlen);
	if (error) {
		sock_d("getsockname() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int getsockname_orig(int sockfd, struct bsd_sockaddr *addr, socklen_t *addrlen)
{
	int error;

	sock_d("getsockname_orig(sockfd=%d, ...)", sockfd);

	error = linux_getsockname(sockfd, addr, addrlen);
	if (error) {
		sock_d("getsockname_orig() failed, errno=%d", error);
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
#if IPBYPASS_ENABLED
	if (fd_is_bypassed(sockfd)) {
		int fd = sockfd;
		sock_info *soinf = sol_find(fd);
		fprintf_pos(stderr, "fd=%d soinf=%p %d\n", fd, soinf, soinf?soinf->fd:-1);
		if(!soinf) {
			return 0;
		}
		uint32_t peer_addr = soinf->peer_addr;
		short peer_port = soinf->peer_port;
		uint32_t peer_id = ipv4_addr_to_id(peer_addr);
		int peer_fd = -1;
		assert(peer_addr != 0xFFFFFFFF && peer_port != 0);
		assert(peer_id != 0);
		// OK, peer seems to be known and our.

		fprintf_pos(stderr, "fd=%d connected with peer_addr=0x%08x peer_port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));

		// isto kot v connect - samo ce imas sendto, potem lahko connect preskocis ...
		fprintf_pos(stderr, "INFO fd=%d me   %s\n", fd, soinf->c_str());
		/*int aa,bb,cc;
		aa = so_bypass_possible(soinf, soinf->my_port);
		bb = so_bypass_possible(soinf, peer_port);
		cc = peer_addr == my_ip_addr;
		fprintf_pos(stderr, "DBG abc %d %d %d\n", aa, bb, cc); */
		sock_info *soinf_peer = nullptr;
		assert(soinf->is_bypass);
		/* vsaj za tcp, bi to zdaj ze moral biti povezano*/
		peer_fd = soinf->peer_fd;
		soinf_peer = sol_find_peer(soinf->peer_fd, peer_addr, peer_port, false); // should be already connected. TODO - kaj pa ce poslusa na specific IP? Potem bom spet napacen sock_info nasel. Bo reba kar extra flag, ali pa s pointerji povezati.
		assert(soinf_peer && soinf_peer->is_bypass);
		fprintf_pos(stderr, "INFO fd=%d peer %s\n", fd, soinf_peer->c_str());

		struct sockaddr_in* in_addr;
		in_addr = (sockaddr_in*)(void*)addr;
		if (addrlen == nullptr || *addrlen < sizeof(struct sockaddr_in)) {
			errno = EINVAL;
			return -1;
		}
		/*
		ker sem videl cisto garbage sa_family v
		btl_tcp_proc.c, mca_btl_tcp_proc_accept()
		"if( btl_endpoint->endpoint_addr->addr_family != addr->sa_family ) {"

		bsd_sockaddr vsebuje char sa_len, char sa_family, sa_data
		linux addr je pa brez tistega len na zacetku, in namesto char sa_family je short sin_family
		*/
		in_addr->sin_family = AF_INET;
		in_addr->sin_addr.s_addr = soinf_peer->my_addr;
		in_addr->sin_port = soinf_peer->my_port;

		return 0;
	}
#endif

	error = linux_getpeername(sockfd, addr, addrlen);
	if (error) {
		sock_d("getpeername() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}

extern "C"
int accept(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len);

extern "C"
int accept4(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len, int flg)
{
#if 1
	// samo goljufam za nginx in ipbypass
	return accept(fd, addr, len);
#else
	int fd2, error;

	sock_d("accept4(fd=%d, ..., flg=%d)", fd, flg);

	error = linux_accept4(fd, addr, len, &fd2, flg);
	if (error) {
		sock_d("accept4() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return fd2;
#endif
}

int accept_bypass(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len, int fd2)
{
	fprintf_pos(stderr, "BUMP fd=%d fd2=%d\n", fd, fd2);
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return 0;
	}
	if (!soinf->is_bypass) {
		return 0;
	}


	//*fd2 = socket_func(PF_INET, SOCK_STREAM, IPPROTO_TCP); // get a VALID fd - for sbwait()
	sock_info *soinf2 = sol_find(fd2);
	fprintf_pos(stderr, "to-be-accepted fd=%d fd2=%d, soinf2=%p\n", fd, fd2, soinf2);
	assert(soinf2 != nullptr);
	    //fprintf(stderr, "to-be-accepted AAA fd=%d fd2=%d, soinf2=%p %s\n", fd, fd2, soinf2, soinf2->c_str());
	// ukradi stanje od soinf
	soinf2->my_id = soinf->my_id;
	soinf2->my_addr = my_ip_addr; //soinf->my_addr; // soinf->my_addr == 0.0.0.0, tipicno. Medtem ko client ve, kam klice.
	soinf2->my_port = soinf->my_port;
	soinf2->bypass(0, 0xFFFFFFFF, 0, -1); // Kje poslusam jaz, vem. Kdo se bo gor povezal, pa ne vem, zato peer fd = -1, in enako vse ostalo od peer-a.
	//
	    //fprintf(stderr, "to-be-accepted BBB fd=%d fd2=%d, soinf2=%p %s\n", fd, fd2, soinf2, soinf2->c_str());
//	assert(soinf2->peer_fd == -1); // kar preverja prejemnik/client
	//usleep(10000);
	soinf->accept_soinf = soinf2;

	mydebug("fd=%d, fd2=%d set is_accepted=true\n", fd, fd2);
	soinf2->is_accepted = true;
	assert(soinf2->listen_soinf != nullptr);
	assert(soinf2->my_port == soinf2->listen_soinf->my_port);

#if 0
	// kdor se povezuje name, bo nastavil peer fd,addr,port.
	do {
		/*
		fprintf_pos(stderr, "fd=%d %d_0x%08x:%d -> %d_0x%08x:%d waiting on client...\n", fd, 
			soinf->fd, ntohl(soinf->my_addr), ntohs(soinf->my_port),
			soinf->peer_fd, ntohl(soinf->peer_addr), ntohs(soinf->peer_port)
			);
		sleep(1);
		*/
 
 		usleep(0);
	} while (/*soinf->peer_fd < 0 &&
		(soinf->peer_addr == 0xFFFFFFFF || soinf->peer_addr == 0x00000000) &&
		soinf->peer_port == 0 &&*/
		soinf->accept_soinf->peer_fd < 0);
#endif
		//(*(volatile int*)(void*)&(soinf->accept_soinf->peer_fd)) < 0);
	// TODO - samo poisci ze allociran sock_info

	// nehaj sprejemati nove povezave
	soinf->accept_soinf = nullptr;
	// TODO - atomic, pa kdor je nastavil, naj se pobrise. soinf->connecting_soinf = nullptr;

	// v addr se vpise peer addr:port
	if (addr &&
		*len >= sizeof(struct sockaddr_in)) {
		memset(addr, 0x00, *len);
		struct sockaddr_in* in_addr;
		//struct sockaddr* in_addr;
		in_addr = (sockaddr_in*)(void*)addr;
		//addr->sa_family = AF_INET;
		*(u_short *)(void*)addr = AF_INET; // linux has family as first short. Compare bsd_to_linux_sockaddr().
		in_addr->sin_addr.s_addr = soinf2->peer_addr;
		in_addr->sin_port = soinf2->peer_port;
		*len = sizeof(struct sockaddr_in);
		fprintf(stderr, "fd=%d Accepted conn we=0x%08x:%d from peer=0x%08x:%d\n", fd, 
			ntohl(soinf2->my_addr), ntohs(soinf2->my_port), ntohl(soinf2->peer_addr), ntohs(soinf2->peer_port));
	}

	// zdaj moram vrniti nov fd za nov socket, tj *fd2

	return 0;
}

extern "C"
int accept(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len)
{
	int fd2, error;
	trace_ipby_accept(gettid(), fd, -1);

	sock_d("accept(fd=%d, ...)", fd);
	fprintf_pos(stderr, "BUMP fd=%d\n", fd);

	error = linux_accept(fd, addr, len, &fd2);
	if (error) {
		sock_d("accept() failed, errno=%d", error);
		errno = error;
		trace_ipby_accept_err(gettid(), fd, fd2);
		return -1;
	}
	fprintf_pos(stderr, "BUMP fd=%d, fd2=%d\n", fd, fd2);

#if IPBYPASS_ENABLED
	// sol_insert() zdaj kern_accept naredi, v dveh delih.
	// sol_insert(fd2, 0);
	error = accept_bypass(fd, addr, len, fd2);
	if(error) {
		errno = error;
		trace_ipby_accept_err(gettid(), fd, fd2);
		return -1;
	}
#endif

	trace_ipby_accept_ret(gettid(), fd, fd2);
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

#if IPBYPASS_ENABLED == 0
	return 0;
#endif

	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		return -1;
	}
	struct sockaddr_in* in_addr;
	in_addr = (sockaddr_in*)(void*)addr;
	soinf->my_addr = in_addr->sin_addr.s_addr;
	soinf->my_port = in_addr->sin_port;
	fprintf_pos(stderr, "fd=%d me (from input addr ) %s\n", fd, soinf->c_str());

	struct bsd_sockaddr addr2;
	socklen_t len2 = sizeof(addr2);
	int ret;
	memset(&addr2, 0x00, len2);
	ret = getsockname_orig(fd, &addr2, &len2);
	if(ret) {
		fprintf_pos(stderr, "ERROR fd=%d getsockname_orig erro ret=%d\n", fd, ret);
		return -1;
	}
	assert(len2 == sizeof(addr2));
	in_addr = (sockaddr_in*)(void*)&addr2;
	assert(soinf->my_id == my_owner_id);
	soinf->my_addr = in_addr->sin_addr.s_addr;
	soinf->my_port = in_addr->sin_port;
	fprintf_pos(stderr, "fd=%d me (from getsockname_orig) %s\n", fd, soinf->c_str());


	// enable bypass for all server-side sockets.
	// But not to early.
	//soinf->bypass();
	//int peer_fd = -1;
	if ( so_bypass_possible(soinf, soinf->my_port) &&
		  (soinf->my_addr == my_ip_addr ||
		   soinf->my_addr == 0x00000000 /*ANY ADDR*/ )
	   ) {
		fprintf_pos(stderr, "INFO fd=%d me %s try to bypass\n", fd, soinf->c_str());
		soinf->bypass(0, 0xFFFFFFFF, 0, -1);
	}
	else {
		fprintf_pos(stderr, "INFO fd=%d me %s bypass not possible\n", fd, soinf->c_str());
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

int connect_from_tcp_etablished_client(int fd, int fd_srv, ushort srv_port)
{
	mydebug("connect_from_tcp_etablished_client fd=%d fd_srv=%d srv_port=%lu\n", fd, fd_srv, ntohs(srv_port));

	sock_info *soinf = sol_find(fd);

	//sock_info *soinf_peer = sol_find_peer(int fd, uint32_t peer_addr, ushort peer_port, bool allow_inaddr_any) sol_find(fd);
	uint32_t peer_addr = soinf->peer_addr; // pogledam, kati, kam
	ushort peer_port = srv_port;
	// peer VM se ni acceptal connection-a - glej kern_accept in fd allokacijo.
	//sleep(2);
	// pa peer se ni vpisal my_fd-ja.
	dump_solist("BEFORE-client-search");
#if 0
	sock_info *sp1 = sol_find_peer(fd, peer_addr, peer_port, false /*allow_inaddr_any*/);
	usleep(1000*100);
	sock_info *sp2 = sol_find_peer(fd, peer_addr, peer_port, false /*allow_inaddr_any*/);
	usleep(1000*100);
	sock_info *sp3 = sol_find_peer(fd, peer_addr, peer_port, false /*allow_inaddr_any*/);
	usleep(1000*100);
	sock_info *sp4 = sol_find_peer(fd, peer_addr, peer_port, false /*allow_inaddr_any*/);
	usleep(1000*100);
	sock_info *soinf_peer = sol_find_peer(fd, peer_addr, peer_port, false /*allow_inaddr_any*/);
	dump_solist("AFTER-client-search");
	mydebug("FFF soinf_peer= %p %p %p %p ... %p\n", sp1, sp2, sp3, sp4, soinf_peer);
#else
	sock_info *soinf_peer = nullptr;
	int ii = 0, dT=1;

	while(ii++ < 10*1000/dT) {
		soinf_peer = sol_find_peer(fd, peer_addr, peer_port, false /*allow_inaddr_any*/);
		if (soinf_peer)
			break;
		usleep(dT);
	}
	printf_early_func("FFF ii=%d soinf_peer= %p\n", ii, soinf_peer);
#endif
	// soinf_peer je NULL, ce ne cakas.
	// delay pe potreben, da ima server cas nastaviti vrednosti.
	// in peer/server fd je ???
#if IPBYPASS_ENABLED==0
	return 0;
#endif
	assert(soinf);
//return 0;
	assert(soinf_peer);// ta je nullptr -> vcasih, ali vedno?
	sol_print(soinf->fd);
	sol_print(soinf_peer->fd);

	dump_solist("after-delay");
	mydebug("found peer soinf_peer=%p: %d_0x%08x:%d -> %d_0x%08x:%d\n", soinf_peer,
		soinf_peer->fd, ntohl(soinf_peer->my_addr), ntohs(soinf_peer->my_port),
		soinf_peer->peer_fd, ntohl(soinf_peer->peer_addr), ntohs(soinf_peer->peer_port));
	soinf_peer->peer_fd = soinf->fd;
	dump_solist("after fix soinf_peer->peer_fd");

	return 0;
}

int accept_from_tcp_etablished_server(int fd, int fd_clnt, uint32_t peer_addr, ushort peer_port)
{
	mydebug("fd=%d fd_clnt=%d\n", fd, fd_clnt);

	struct bsd_sockaddr peer_soaddr;
	socklen_t peer_soaddr_len = sizeof(peer_soaddr);
	linux_getpeername(fd, &peer_soaddr, &peer_soaddr_len); // ker je fd oznacen kot bypassed, klici linux_getpeername, ne getpeername
	struct sockaddr_in *ss = (struct sockaddr_in *)&peer_soaddr;
	peer_port = ss->sin_port;
	peer_addr = ss->sin_addr.s_addr;
	mydebug("fd=%d fd_clnt=%d, peer_addr/NET=0x%08x, peer_port/HOST=%d\n", fd, fd_clnt, peer_addr, ntohs(peer_port));
	return 0;
}

// PA ze v bind treba bypass prizgati, ce se le da...
extern "C"
int connect(int fd, const struct bsd_sockaddr *addr, socklen_t len)
{
	int error;

	trace_ipby_connect(gettid(), fd);
	sock_d("connect(fd=%d, ...)", fd);
#if IPBYPASS_ENABLED
	fprintf_pos(stderr, "INFO connect fd=%d\n", fd);

	// if we connect to intra-host VM, use bypass
	// OR, if we connect to the same-VM, use bypass
	sock_info *soinf = sol_find(fd);
	if (soinf == nullptr) {
		fprintf_pos(stderr, "ERROR fd=%d not found\n", fd);
		trace_ipby_connect_err(gettid(), fd);
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
	uint32_t peer_id = ipv4_addr_to_id(peer_addr);
	sock_info *soinf_peer = nullptr;

	// blacklist port 8000 - REST api
	if (peer_port == htons(8000)) {
		soinf->is_bypass = false;
		fprintf_pos(stderr, "DO NOT BYPASS PORT 8000, soinf=%p %s\n", soinf, soinf->c_str());
		goto do_linux_connect;
	}

	//bool do_linux_connect = true;
	fprintf_pos(stderr, "INFO connect fd=%d peer addr=0x%08x,port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));
	if ( (so_bypass_possible(soinf, soinf->my_port) ||
		  so_bypass_possible(soinf, peer_port) ) &&
		  (
			(peer_addr == my_ip_addr) || true || /* peer_addr ni vec treba, da je moj - sedaj podpiramo dve VM */

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
			soinf_peer = sol_find_peer_listening(fd, peer_addr, peer_port); // client se povezuje na server
		}
		else {
			// najbrz smo server, ki se povezuje nazaj na clienta.
			// peer of peer-a sem jaz logika
			// oz kdor ima mene za peer-a, tistega bom jaz imel za peer-a.
			assert(0);
			soinf_peer = sol_find_peer2(fd, soinf->my_addr, soinf->my_port);
		}

		//assert(soinf_peer != nullptr); // ali pa implementiraj se varianto "najprej client, potem server"
		// Client pomotoma pozenme prej kot server, in naj bo potem lep error/exit.
		if (soinf_peer == nullptr) {
			errno = ECONNREFUSED;
			trace_ipby_connect_err(gettid(), fd);
			return -1;
		}

		peer_fd = soinf_peer->fd;
		fprintf_pos(stderr, "INFO connect fd=%d me %s to peer %d:%d_0x%08x:%d try to bypass\n",
			fd, soinf->c_str(),
			peer_id, peer_fd, ntohl(peer_addr), ntohs(peer_port));
		if(soinf->is_bypass) {
			fprintf_pos(stderr, "INFO already bypass-ed fd me/peer %d %d.\n", fd, peer_fd);
			//assert(0);
			// hja, zdaj pa is_bypass je ze true, peer_* pa na defualt vrednostih . jej jej jej. 
		}
		else {
			// se izvede
			soinf->bypass(0, -1/*peer_addr*/, 0, -1/*peer_fd*/);
		}
		soinf->peer_id = peer_id;
		soinf->peer_fd = -1; // to je od listen socket - peer_fd;
		soinf->peer_addr = peer_addr;
		soinf->peer_port = peer_port;
	}
	else {
		fprintf_pos(stderr, "INFO connect fd=%d me %s peer %d:%d_0x%08x:%d bypass not possible\n",
			fd, soinf->c_str(), peer_id, peer_fd, ntohl(peer_addr), ntohs(peer_port));
	}

	fprintf_pos(stderr, "INFO connect new_state fd=%d %s\n", fd, soinf->c_str());

	/* ta connect crkne, ce je to UDP server - t.j. bind, nato connect. Vmes moras vsaj en paket prejeti?
	Samo potem, ko preskocim connect, me pa zaj naslednji server socket, ko nov thread javi "bind failed: Address in use".
	 */
	if (in_addr->sin_port == 0) {
		//do_linux_connect = false;
		// server se hoce connectat-i nazaj na clienta, samo zaradi bypass ni izvedel pravega porta.
		// dodaj se eno goljufijo vec...
		fprintf(stderr, "INFO INFO INFO connect fd=%d insert faked addr/port from soinf_peer %s\n",
			fd, soinf_peer->c_str());
		in_addr->sin_addr.s_addr = soinf_peer->my_addr;
		in_addr->sin_port = soinf_peer->my_port;
	}
	fprintf(stderr, "INFO linux_connect fd=%d to in_addr 0x%08x:%d\n",
		fd, ntohl(in_addr->sin_addr.s_addr), ntohs(in_addr->sin_port));

	// To naredi pred linux_connect, da poll koda deluje
	// TODO: Mixing of normal and byapssed clients will still be a problem, I guess.
// tega zdaj vec ne bom rabil.
#if 0
	if(soinf_peer) {
		//soinf_peer->connecting_soinf = soinf;

		static_assert(sizeof(std::atomic<sock_info*>) == sizeof(sock_info*), "Vsaj velikostyi bi morale biti enake, da je cast morda OK.");
		std::atomic<sock_info*>* a_conn_soinf = (std::atomic<sock_info*>*)(void*)&soinf_peer->connecting_soinf;
		sock_info *expected = nullptr;
		fprintf_pos(stderr, "INFO fd=%d set ATOMIC connecting_soinf before: obj=%p expected=%p, soinf=%p \n", fd, a_conn_soinf->load(), expected, soinf);
		int cnt = 0;
		bool exchange_done = false;
		do {
			expected = nullptr;
			exchange_done = a_conn_soinf->compare_exchange_weak(expected, soinf);
			cnt++;
		} while (!exchange_done);
		fprintf_pos(stderr, "INFO fd=%d set ATOMIC connecting_soinf after : obj=%p expected=%p, soinf=%p cnt=%d\n", fd, a_conn_soinf->load(), expected, soinf, cnt);
		assert(soinf_peer->connecting_soinf == soinf);
	}
#endif

	// allociraj soinf za server VM soinf_srv. soinf_srv->listen_soinf nastavi na soinf_peer, da je oznacen,
	// in ga bo server lahko nasel. soinf_srv - nastavi moj fd,addr,port,peer_addr,peer_port; edino peer_fd se ni znan -
	// tega bo nastavil server, najbrz kar iz kern_accept.
	// ker bom novemu soinf_srv nastavil soinf_srv->listen_soinf, ni treba atomic exchnage.
	// Hm - je tu se kaj takaga, da bi moral cakati na ta nekaj?

do_linux_connect:
#endif

	// ta bo naredil server listen()-ing fd soreadable() - glej uppc_socket.cc, sopoll_generic_locked()
	error = linux_connect(fd, (void *)addr, len);
	if (error) {
		sock_d("connect() failed, errno=%d", error);
		fprintf_pos(stderr, "ERROR connect() failed, errno=%d\n", error);
		errno = error;
#if IPBYPASS_ENABLED == 0
		trace_ipby_connect_err(gettid(), fd);
		return -1;
#endif

		if(error == EINPROGRESS) {
			// http://stackoverflow.com/questions/8277970/what-are-possible-reason-for-socket-error-einprogress-in-solaris
			// nonblocking socket, our port:ip is already known. Try to continue.
			fprintf(stderr, "ERROR connect() failed, errno=%d EINPROGRESS, try to continue\n", error);
			//sleep(3);
	}
		else {
			// no, pa dajmo probati to na tiho ignorirati :/
			// sej je samo mali iperf server problem....
			fprintf(stderr, "ERROR connect() failed, errno=%d NA TIHEM IGNORIRAM< da bo vsaj iperf server nekaj lahko vrnil. Tudi ce potem crashne...\n", error);
			trace_ipby_connect_ret(gettid(), fd);
			return 0;
		}
	}

#if IPBYPASS_ENABLED
	if (soinf->is_bypass == false) {
		// client port is blacklisted - 8000, we disabled bypass.
		trace_ipby_connect_ret(gettid(), fd);
		return 0;
	}

	// ce se ne poznam moje addr/port
	// BUG - ISR lahko dobi syn-ack, in isce moj addr/port, pa ga ne najde.
	// ker ga connect user thread se ni nastavil/shranil. Razen ,ce vedno iscem samo po fd-ju.
	//
	//int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	fprintf_pos(stderr, "INFO soinf before-1: %s\n", soinf->c_str());
	if (soinf->my_port == 0 || soinf->my_addr == 0xFFFFFFFF || soinf->my_addr == 0x00000000) {
		// syn se je (verjetno) ze poslal. Najbrz ga je peer VM tudi ze prejel.
		// Ziher pa zdajle ze lahko vprasmo za moj src_ip/port.
		struct bsd_sockaddr addr2;
		socklen_t addr2_len = sizeof(addr2);
		error = getsockname_orig(fd, &addr2, &addr2_len);
		if (error) {
			sock_d("connect / getsockname_orig() failed, error=%d", error);
			fprintf_pos(stderr, "ERROR connect / getsockname_orig() failed, error=%d\n", error);
			trace_ipby_connect_err(gettid(), fd);
			return -1;
		}
		struct sockaddr_in* in_addr2 = (sockaddr_in*)(void*)&addr2;
		soinf->my_addr = in_addr2->sin_addr.s_addr;
		soinf->my_port = in_addr2->sin_port;
		fprintf_pos(stderr, "INFO soinf after-1: %s\n", soinf->c_str());
		//
#if 0
/*
To je zdaj v ISR, popravljanje se zadnjega manjkajocega fd-ja.

Morda je pomembno, da vrnem prej, kot pa dobim nazaj syn-ack.
Tj, da epoll wait zacnem, preden dobim syn-ack.
morda?
Zdi se ze tako. Pa vsaj en race se vedno ostaja.
No, wrk je tudi imel bug, arry beoyd-end usage.
Je bil to glavni problem?
*/
		// da ni prehiter.
		// TODO - to bi moral zakasniti, in naredit potem, ko dobim nazaj syn-ack.
		// ker takrat pa vem, da je server ze naredil svoj sock_info.
		//sleep(2);
		dump_solist("before-delay");
		usleep(1000*200);
		//
		mydebug("searching for peer: me:?_0x%08x:%d -> peer:?_0x%08x:%d\n",
			ntohl(soinf->my_addr), ntohs(soinf->my_port), ntohl(peer_addr), ntohs(peer_port));
		// soinf2->peer_fd  se ni nastavljen, ker ga server se ni vedel.
		// soinf2->fd se ni nastavlen, ker server takrat se ni imle allociranega fd-ja.
		sock_info *soinf2 = nullptr;
		for (int ii=0; ii<10; ii++) {
			soinf2 = sol_find_full(-1, peer_addr, peer_port, -1, soinf->my_addr, soinf->my_port);
			if (soinf2)
				break;
			usleep(1000*500);
		}
		dump_solist("after-delay");
		assert(soinf2);
		mydebug("found peer soinf2=%p: %d_0x%08x:%d -> %d_0x%08x:%d\n", soinf2,
			soinf2->fd, ntohl(soinf2->my_addr), ntohs(soinf2->my_port),
			soinf2->peer_fd, ntohl(soinf2->peer_addr), ntohs(soinf2->peer_port));

		// naj to raje client ISR naredi -> connect_from_tcp_etablished_client
		//soinf2->peer_fd = fd;

		//soinf2->fd == soinf->peer_fd == ? // to bi pa server moral nastaviti. Potem ko ve.

		//usleep(1000);
		fprintf_pos(stderr, "INFO connect soinf updated fd=%d %s\n", fd, soinf->c_str());
		fprintf_pos(stderr, "INFO connect soinf_peer    fd=%d %s\n", fd, soinf_peer->c_str());
		fprintf_pos(stderr, "INFO connect soinf2        fd=%d %s\n", fd, soinf2->c_str());
#endif
	}
	if (0) { // if (soinf->my_port == 0 || soinf->my_addr == 0xFFFFFFFF || soinf->my_addr == 0x00000000) {
		// OLD code
		struct bsd_sockaddr addr2;
		socklen_t addr2_len = sizeof(addr2);
		error = getsockname_orig(fd, &addr2, &addr2_len);
		if (error) {
			sock_d("connect / getsockname_orig() failed, error=%d", error);
			fprintf_pos(stderr, "ERROR connect / getsockname_orig() failed, error=%d\n", error);
			trace_ipby_connect_err(gettid(), fd);
			return -1;
		}
		struct sockaddr_in* in_addr2 = (sockaddr_in*)(void*)&addr2;
		soinf->my_addr = in_addr2->sin_addr.s_addr;
		soinf->my_port = in_addr2->sin_port;
		fprintf_pos(stderr, "INFO soinf after-1: %s\n", soinf->c_str());


		// TODO TCP daj nastiv se za peer_fd, da bo accept_bypass sel naprej
		// setup also peer, so that tcp accept_bypass continues
		int loop_flag = 0;
		//
		// Recimo, da ze linux_connect() sprozi check, ce je socket readable.
		// In ker nocem preverjati via soreadabledata (v sopoll_generic_locked(), ce je fd byapssed),
		// potem ne vidim, da je readable. Kasneje se pa vec ne izvede preverjanje.
		// Preverjam samo via soi_is_readable(), ki pogleda tudi connecting_soinf.
		// Zato bom tega nastavil ze pred linux_connect().
		//soinf_peer->connecting_soinf = soinf;
		//
		while(soinf_peer->accept_soinf == nullptr) {
			if(loop_flag == 0)
				fprintf_pos(stderr, "INFO waiting on soinf_peer->accept_soinf to be valid...\n", "");
			usleep(0); // ker server mogoce se ni svoje priprave za accept koncal.
			loop_flag = 1;
		}
		assert(soinf_peer->accept_soinf != nullptr);
		fprintf_pos(stderr, "connecting fd=%d to peer->fd=%d, on new peer->accept_soinf->fd=%d\n", fd, soinf_peer->fd, soinf_peer->accept_soinf->fd);
		sock_info *soinf2 = soinf_peer->accept_soinf;
		assert(soinf2->peer_fd == -1);
		// ukradi stanje od soinf
		// soinf2->my_addr = soinf->peer_addr; // soinf_peer->my_addr == 0.0.0.0, tipicno. Medtem ko client ve, kam klice.
		assert(soinf2->my_addr == 0 || soinf2->my_addr == -1 || soinf2->my_addr == soinf->peer_addr); // pricakujem, da je enako, vem pa ne
		soinf2->my_addr = soinf->peer_addr;
		assert(soinf2->my_port == soinf_peer->my_port);
		//soinf2->peer_fd = soinf->fd; // ta je nazadnje
		soinf2->peer_id = soinf->my_id;
		soinf2->peer_addr = soinf->my_addr;
		soinf2->peer_port = soinf->my_port;

		// popravi se sebe
		soinf->peer_fd = soinf2->fd;
		// cisto nazadnje
		soinf2->peer_fd = fd; // == soinf_peer->accept_soinf->peer_fd , flag za cakanje

		std::atomic<sock_info*>* a_conn_soinf = (std::atomic<sock_info*>*)(void*)&soinf_peer->connecting_soinf;
		sock_info *expected = soinf;
		fprintf_pos(stderr, "INFO fd=%d set ATOMIC connecting_soinf before reset: obj=%p expected=%p, soinf=%p \n", fd, a_conn_soinf->load(), expected, soinf);
		int cnt = 0;
		bool exchange_done = false;
		do {
			expected = soinf;
			exchange_done = a_conn_soinf->compare_exchange_weak(expected, nullptr);
			cnt++;
		} while (!exchange_done);
		fprintf_pos(stderr, "INFO fd=%d set ATOMIC connecting_soinf after reset : obj=%p expected=%p, soinf=%p cnt=%d\n", fd, a_conn_soinf->load(), expected, soinf, cnt);
		assert(expected == soinf);

#if 1
		// after some delay, this should be true
		int ii;
		for (ii=0; ii<1000* 10; ii++) {
			if (soinf_peer->connecting_soinf != soinf)
				break;
			usleep(1000*1);
		}
		fprintf_pos(stderr, "INFO waiting on soinf_peer->connecting_soinf to be NULL, ii=%d, connecting_soinf=%p...\n", ii, soinf_peer->connecting_soinf);
		assert(soinf_peer->connecting_soinf != soinf); // most often, should be == NULL
#endif

		fprintf_pos(stderr, "INFO connect soinf updated fd=%d %s\n", fd, soinf->c_str());
		fprintf_pos(stderr, "INFO connect soinf_peer    fd=%d %s\n", fd, soinf_peer->c_str());
		fprintf_pos(stderr, "INFO connect soinf2        fd=%d %s\n", fd, soinf2->c_str());
	}
#endif

	trace_ipby_connect_ret(gettid(), fd);
	return 0;
}

extern "C"
int listen(int fd, int backlog)
{
	int error;

	sock_d("listen(fd=%d, backlog=%d)", fd, backlog);
	fprintf_pos(stderr, "INFO listen fd=%d\n", fd);

	error = linux_listen(fd, backlog);
	if (error) {
		sock_d("listen() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return 0;
}


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

	trace_ipby_recvfrom_bypass(gettid(), fd);
	size_t available_read=0;
 	sock_info *soinf = sol_find(fd);
	//fprintf_pos(stderr, "soinf=%p %d\n", soinf, soinf?soinf->fd:-1);
	assert(soinf && soinf->is_bypass);
	fprintf_pos(stderr, "fd=%d len=%d BYPASS-ed\n", fd, len);

	// ta fd je ze bil pobrisan, in je neveljaven
	if (soinf->flags & SOR_DELETED) {
		errno = EBADF;
		trace_ipby_recvfrom_bypass_err(gettid(), fd);
		return -1;
	}
	// shutdown ali close je ze bil klican, SOR_CLOSED je nastavljen - read se lahko vrne se-neprebrane podatke

	// ce sem od prejsnjega branja dobil dva pakate, potem sem dvakrat nastavil flag/event za sbwait.
	// ampak sbwait() bo sedaj samo enkrat pocistil, 
	// tako da, ce podatki so, potem jih beri brez sbwait() cakanja.

	//if( soinf->ring_buf.available_read() <= sizeof(RingMessageHdr) ) { // za UDP, kjer imam header
	short *so_rcv_state = nullptr;
	int error;
	struct file *fp;
	struct socket *so;
	error = getsock_cap(fd, &fp, NULL);
	if (error) {
		trace_ipby_recvfrom_bypass_err(gettid(), fd);
		return (error);
	}
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	//SOCK_LOCK(so);  // ce dam stran: Assertion failed: SOCK_OWNED(so) (bsd/sys/kern/uipc_sockbuf.cc: sbwait_tmo: 144)
	// netperf naredi shutdown, potem pa hoce prebrati se preostanek podatkov.
	//
	so_rcv_state = &so->so_rcv.sb_state;
	//SOCK_UNLOCK(so);

	// trace_ipby_recvfrom_bypass_info(gettid(), fd, __LINE__, "info-1");
	if( (available_read = soinf->ring_buf.available_read()) <= 0 ) { // za TCP, kjer nimam headerja

		/* bsd/sys/kern/uipc_syscalls.cc:608 +- eps */
		//SOCK_LOCK(so);  // ce dam stran: Assertion failed: SOCK_OWNED(so) (bsd/sys/kern/uipc_sockbuf.cc: sbwait_tmo: 144)
		// netperf naredi shutdown, potem pa hoce prebrati se preostanek podatkov.
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE == 0) { // TODO
			SOCK_LOCK(so);
			error = sbwait(so, &so->so_rcv);
			SOCK_UNLOCK(so);
		}
		//
		available_read = soinf->ring_buf.available_read();
		fprintf_pos(stderr, "fd=%d so_state=0x%x so->so_rcv.sb_state=0x%x available_read=%d\n",
			fd, so->so_state, so->so_rcv.sb_state, available_read);
		// if (so->so_state == SS_ISDISCONNECTED) {
#if 0
		if (available_read == 0 &&
			so->so_rcv.sb_state & SBS_CANTRCVMORE) { // TODO
			fprintf_pos(stderr, "fd=%d so_state=0x%x SS_ISDISCONNECTED  so->so_rcv.sb_state=0x%x SBS_CANTRCVMORE=0x%x\n", fd, so->so_state, so->so_rcv.sb_state, SBS_CANTRCVMORE);
			//errno = ENOTCONN;
			errno = EINTR; // to be netperf friendly
			//SOCK_UNLOCK(so);
			fdrop(fp); /* TODO PAZI !!! */
			return -1; // -errno
		}
#endif
		if (available_read == 0) {
			if (soinf->flags & SOR_CLOSED) { // TODO
				fprintf_pos(stderr, "fd=%d soinf->flags=0x%x SOR_CLOSED\n", fd, soinf->flags);
				//errno = ENOTCONN;
				errno = EINTR; // to be netperf friendly
				//SOCK_UNLOCK(so);
				fdrop(fp); /* TODO PAZI !!! */
				trace_ipby_recvfrom_bypass_err(gettid(), fd);
				return -1; // -errno
			}
			else if (soinf->flags & SOR_NONBLOCK) {
				// something for openmpi, see read_bytes at orte/mca/oob/tcp/oob_tcp_sendrecv.c:319
				// Try to return EINTR, EAGAIN or EWOULDBLOCK
				//usleep(1000*1000);
				fprintf_pos(stderr, "fd=%d soinf->flags=0x%x SOR_NONBLOCK\n", fd, soinf->flags);
				errno = EWOULDBLOCK;
				fdrop(fp); /* TODO PAZI !!! */
				trace_ipby_recvfrom_bypass_err(gettid(), fd);
				return -1;
			}
		}
	}
	// trace_ipby_recvfrom_bypass_info(gettid(), fd, __LINE__, "info-2");

	/*
	Socket je bypass-ed. Ne smem iti recvfrom -> linux_recvfrom, ker utegne tam neskoncno dolgo viseti.
	Ali pa morda tudi kak paket pozabi (ker preveckrat kilcem sbwait()?)
	Torej bom kar probal cakati na podatke ;?>

	to mi bo morda spet zj... iperf :/
	// if (soinf->ring_buf.available_read() > sizeof(RingMessageHdr))
	*/
	size_t len2;
	//sleep(1);
	//available_read = soinf->ring_buf.available_read();
	fprintf_pos(stderr, "fd=%d available_read=%d\n", fd, available_read);

#if 0
	// zgleda, da netserver to razume kot napako, in zapre oba svoja socketa
	if (available_read == 0) {
		// to je npr na drugi strani zaprt socket
		//TODO mozno, da mi pokvari kak drug primer (blocking read etc...)
		fprintf_pos(stderr, "fd=%d SKIP reading available_read=%d\n", fd, available_read);
		return 0;
	}
#endif

	//SOCK_UNLOCK(so); // ker data_pop caka na podatke
	// trace_ipby_recvfrom_bypass_info(gettid(), fd, __LINE__, "info-3");
	len2 = soinf->data_pop(buf, len/*, so_rcv_state*/); /* tule obvisi , pri prvem klicu, za par sec. */
	// trace_ipby_recvfrom_bypass_info(gettid(), fd, __LINE__, "info-4");
	fprintf_pos(stderr, "fd=%d data_pop len2=%d\n", fd, len2);

	SOCK_LOCK(so);  // ce dam stran: Assertion failed: SOCK_OWNED(so) (bsd/sys/kern/uipc_sockbuf.cc: sbwait_tmo: 144)
	// via so->so_rcv.sb_cc does poll_scan -> socket_file::poll -> sopoll -> sopoll_generic -> sopoll_generic_locked 
	// -> soreadabledata detects that there are readable data
	so->so_rcv.sb_cc -= len2; // a treba imeti so locked ?

	SOCK_UNLOCK(so);
	// trace_ipby_recvfrom_bypass_info(gettid(), fd, __LINE__, "info-5");
	fdrop(fp); /* TODO PAZI !!! */

	trace_ipby_recvfrom_bypass_ret(gettid(), fd);
	return len2;
}

extern "C"
ssize_t recvfrom(int fd, void *__restrict buf, size_t len, int flags,
		struct bsd_sockaddr *__restrict addr, socklen_t *__restrict alen)
{
	int error;
	ssize_t bytes;

	sock_d("recvfrom(fd=%d, buf=<uninit>, len=%d, flags=0x%x, ...)", fd,
		len, flags);
 
	if(fd_is_bypassed(fd)) {
		ssize_t len2 = recvfrom_bypass(fd, buf, len);
		return len2;
	}

	// tudi tu se klice sbwait. IZgleda, da ne moti, da ponoven klic brez predhodnega branja podatkov takoj neha cakatai.
	error = linux_recvfrom(fd, (caddr_t)buf, len, flags, addr, alen, &bytes);
	if (error) {
		sock_d("recvfrom() failed, errno=%d", error);
		errno = error;
		return -1;
	}

	return bytes;
}

extern "C"
ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	int error;
	ssize_t bytes;

	sock_d("recv(fd=%d, buf=<uninit>, len=%d, flags=0x%x)", fd, len, flags);
	
	if(fd_is_bypassed(fd)) {
		ssize_t len2 = recvfrom_bypass(fd, buf, len);
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
	if(fd_is_bypassed(fd)) {
		ssize_t len2 = recvfrom_bypass(fd, buf, len);
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


int wake_foreigen_socket(int peer_fd, int len2) {
	/* bsd/sys/kern/uipc_syscalls.cc:608 +- eps */
	int error;
	struct file *fp;
	struct socket *so;
	error = getsock_cap(peer_fd, &fp, NULL); /* za tcp tu vec nimam pravega fd-ja :/ */
	if (error)
		return (error);
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	SOCK_LOCK(so);
	//
	//error = sbwait(so, &so->so_rcv);
	// via so->so_rcv.sb_cc does poll_scan -> socket_file::poll -> sopoll -> sopoll_generic -> sopoll_generic_locked 
	// -> soreadabledata detects that there are readable data
	so->so_rcv.sb_cc += len2; // and so->so_rcv.sb_cc_wq wake_all ??
	//so->so_nc_wq.wake_all(SOCK_MTX_REF(so)); // tega lahko izpustim
	so->so_rcv.sb_cc_wq.wake_all(SOCK_MTX_REF(so)); // ta mora biti
	//
	// tole je pa za poll()
	// a potem mogoce zgornjega so->so_nc_wq.wake_all vec ne rabim?
	//	int poll_wake(struct file* fp, int events)
	// Tudi tega zdaj lahko izpustim? Ali pa ne, potem spet obvisi.
	int events = 1; // recimo, da je 1 ok :/
	poll_wake(fp, events);
	//
	SOCK_UNLOCK(so);
	fdrop(fp); /* TODO PAZI !!! */
	return 0;
}

/*
Recimo, da bi zdaj:
 VM1 nastavila en flag v ivshmem
 VM0 pa bere tisti flag, in ko ga vidi, klice wake_foreigen_socket()
 VM0 dobi dodaten scanner thread, ali pa to pocnem v idle threadu/threadih
 Nekoc bi potem VM0 moral ta "notification" dobiti via interrupt.
 flag - vsak ring_buffer naj ima svoj flag, VM0 potem skenira vse flag-e.
*/

void* bypass_scanner(void *args) {
	bool modified;
	int len2;
	//size_t readable_len = 0;
	fprintf(stderr, "bypass_scanner START, args=%p\n", args);

	while (1) {
		if (so_list == nullptr) {
			sleep(1);
			continue;
		}
		len2 = 0;
		sock_info *soinf;
		int ii;
		for (ii = 0; ii < SOCK_INFO_LIST_LEN; ii++) {
			soinf = (*so_list)[ii];
			if(soinf == nullptr)
				continue;
			if(soinf->my_id != my_owner_id)
				continue;
			modified = soinf->modified.load(std::memory_order_acquire);
			if (
				modified
				//|| 0 < (readable_len = soinf->ring_buf.available_read())
				) {
				soinf->scan_mod++;
				assert(soinf->scan_mod > 0); // chech wrap around
				soinf->modified.store(false, std::memory_order_release);
				len2 = 1; //32k
				fprintf_pos(stderr, "fd=%d soinf=%p is modified, WAKE UP\n", soinf->fd, soinf);
				//sleep(2); // kaj ce server zbudim, se preden pripravi poll/libevent handler?
				wake_foreigen_socket(soinf->fd, len2);
			}
			else {
				soinf->scan_old++;
				assert(soinf->scan_old > 0); // chech wrap around
			}
			if (/*!modified && */ soinf->flags & SOR_CLOSED) {
				// a so sedaj vsi zbujeni ze koncali z delom? Nisem ziher...
				// !modified check bi samo zakasnil za en cikel.
				fprintf_pos(stderr, "fd=%d soinf=%p is SOR_CLOSED, REMOVE\n", soinf->fd, soinf);
			    sol_remove(soinf->fd, -1); // ampak, ce je socket shutdown, se se vedno lahko bere iz njega.
			}
		}
		if (len2 == 0) {
			// no socket was modified, sleep a bit
			// usleep(0);
		}
	}
	fprintf(stderr, "bypass_scanner DONE, args=%p\n", args);
	return 0;
}

ssize_t sendto_bypass(int fd, const void *buf, size_t len, int flags,
    const struct bsd_sockaddr *addr, socklen_t alen) {

	//return len;
	trace_ipby_sendto_bypass(gettid(), fd);
 	sock_info *soinf = sol_find(fd);
	// printf_early_func("SEND: %d %s\n", strlen((const char*)buf), buf);
	fprintf_pos(stderr, "fd=%d len=%d soinf=%p %d\n", fd, len, soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		trace_ipby_sendto_bypass_ret(gettid(), fd);
		return 0;
	}
	if (!soinf->is_bypass) {
		trace_ipby_sendto_bypass_ret(gettid(), fd);
		return 0;
	}
	if (soinf->flags & SOR_DELETED) {
		errno = EBADF;
		trace_ipby_sendto_bypass_err(gettid(), fd);
		return -1;
	}
	if (soinf->flags & SOR_CLOSED) {
		errno = ESHUTDOWN;
		trace_ipby_sendto_bypass_err(gettid(), fd);
		return -1;
	}

	uint32_t peer_id = 0;
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
	peer_id = ipv4_addr_to_id(peer_addr);

	assert(peer_addr != 0xFFFFFFFF && peer_port != 0);
	assert(peer_id != 0);
	// OK, peer seems to be known and our.

	fprintf_pos(stderr, "fd=%d connecting to peer_addr=0x%08x peer_port=%d\n", fd, ntohl(peer_addr), ntohs(peer_port));



	// isto kot v connect - samo ce imas sendto, potem lahko connect preskocis ...
	fprintf_pos(stderr, "INFO fd=%d me   %s\n", fd, soinf->c_str());
	/*int aa,bb,cc;
	aa = so_bypass_possible(soinf, soinf->my_port);
	bb = so_bypass_possible(soinf, peer_port);
	cc = peer_addr == my_ip_addr;
	fprintf_pos(stderr, "DBG abc %d %d %d\n", aa, bb, cc); */
	sock_info *soinf_peer = nullptr;
	assert(soinf->is_bypass);
	/* vsaj za tcp, bi to zdaj ze moral biti povezano*/
	peer_fd = soinf->peer_fd;
	soinf_peer = sol_find_full(soinf->peer_fd, peer_addr, peer_port, fd, soinf->my_addr, soinf->my_port); // should be already connected. TODO - kaj pa ce poslusa na specific IP? Potem bom spet napacen sock_info nasel. Bo reba kar extra flag, ali pa s pointerji povezati.
	if(soinf_peer == nullptr) {
		// hm, client je zaprl svoj socket. Recimo...
		errno = ECONNRESET;
		trace_ipby_sendto_bypass_err(gettid(), fd);
		return -1;
	}
	assert(soinf_peer && soinf_peer->is_bypass);

	// tole je bilo za udp
	/* soinf_peer = sol_find_me(fd, peer_addr, peer_port);
	if(!soinf_peer) {
		fprintf_pos(stderr, "ERROR no valid peer found me/peer %d %d, soinf_peer=%p.\n", fd, peer_fd, soinf_peer);
		return 0;
	}
	peer_fd = soinf_peer->fd; */
	fprintf_pos(stderr, "INFO fd=%d peer %s\n", fd, soinf_peer->c_str());




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

	assert(soinf_peer->is_bypass);
	assert(soinf_peer->ring_buf.data);
	size_t len2=0;
	len2 = soinf_peer->data_push(buf, len);
	//sleep(1);

	// zmeden - a probm tu potem uporabit ptr od tuje VM?? potem getsock_cap crkne, in je tale vrstica noop.
	// No, najbrz ne rabim
	// wake_foreigen_socket(soinf_peer->fd, len2);

	soinf_peer->modified.store(true, std::memory_order_release);
	//fprintf_pos(stderr, "fd=%d marking peer_fd=%d as modified\n", fd, soinf_peer->fd);
//SENDTO_BYPASS_USLEEP(1000*200);
	trace_ipby_sendto_bypass_ret(gettid(), fd);
	return len2;

	/*
	iz sbwait_tmo()
	sched::thread::wait_for(SOCK_MTX_REF(so), *so->so_nc, sb->sb_cc_wq, tmr, sc);
	so->so_nc_busy = false;
	so->so_nc_wq.wake_all(SOCK_MTX_REF(so));
	*/
}

extern "C"
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    const struct bsd_sockaddr *addr, socklen_t alen)
{
	int error;
	ssize_t bytes;

	sock_d("sendto(fd=%d, buf=..., len=%d, flags=0x%x, ...", fd, len, flags);

#if IPBYPASS_ENABLED
	fprintf_pos(stderr, "INFO sendto fd=%d len=%d\n", fd, len);
	ssize_t len2 = sendto_bypass(fd, buf, len, flags, addr, alen);
	if (len2) {
		// a ce vsaj en paket posljme, bo potem lahko server se en connect naredil ?? Please please please...
		// no, mogoce ok za netperf/iperf
		// za redis pa ni ok, socket ostane redable, ker recvfrom_bypass vzame samo podatke iz ring_buffer, pravi socket pa preskocim.
		// Torej bolje, da niti ne vpisujem. Hm, ne pomaga.
		//error = linux_sendto(fd, (caddr_t)buf, len, flags, (caddr_t)addr,
		//		   alen, &bytes);

		return len2;
	}
	if (fd_is_bypassed(fd)) {
		return len2;
	}
#endif

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

void set_cantrecvanymore(int fd) {
	// somehow, signal that bypassed socket is closed, so that the other side, trying to recv, will get a wake.
	struct file *fp;
	struct socket *so;
	int error;
	error = getsock_cap(fd, &fp, NULL); /* za tcp tu vec nimam pravega fd-ja :/ */
	if (error) {
		fprintf_pos(stderr, "fd=%d getsock_cap failed error=%d\n", fd, error);
		return;
	}
	so = (socket*)file_data(fp);
	/* bsd/sys/kern/uipc_socket.cc:2425 */
	SOCK_LOCK(so);
	//
	//so->so_error = 1;
	//so->so_state = SS_ ?;
	fprintf_pos(stderr, "fd=%d old so_state=0x%x so->so_rcv.sb_flags=0x%x\n", fd, so->so_state, so->so_rcv.sb_flags);
	//so->so_state = SS_ISDISCONNECTED;
	//so->so_rcv.sb_flags;
	socantrcvmore_locked(so); // da nastavi so->so_rcv.sb_flags;
	fprintf_pos(stderr, "fd=%d new1 so_state=0x%x so->so_rcv.sb_flags=0x%x\n", fd, so->so_state, so->so_rcv.sb_flags);
	//
	so->so_nc_wq.wake_all(SOCK_MTX_REF(so));
	so->so_rcv.sb_cc_wq.wake_all(SOCK_MTX_REF(so));
	//so_peer->so_nc_wq.wake_all(*so_peer->so_mtx);
	//so_peer->so_rcv.sb_cc_wq.wake_all(*so_peer->so_mtx);
	//
	// tole je pa za poll()
	// a potem mogoce zgornjega so->so_nc_wq.wake_all vec ne rabim?
	//	int poll_wake(struct file* fp, int events)
	int events = 1; // recimo, da je 1 ok :/
	poll_wake(fp, events);
	//
	SOCK_UNLOCK(so);
	//
	//socantrcvmore(so); // da nastavi so->so_rcv.sb_flags;
	fprintf_pos(stderr, "fd=%d new2 so_state=0x%x so->so_rcv.sb_flags=0x%x\n", fd, so->so_state, so->so_rcv.sb_flags);
	//
	fdrop(fp); /* TODO PAZI !!! */
}

int sol_print(int fd)
{
	sock_info *soinf = sol_find(fd);
	int peer_fd = -1;
	fprintf_pos(stderr, "fd=%d soinf=%p %d\n", fd, soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		fprintf(stderr, "INFO sock_info, fd=%d peer_fd=%d soinf==NULL\n",
			fd, peer_fd);
		return 0; /* hb 	*/
	}
	peer_fd = soinf->peer_fd;

	size_t wpos_cum=0, rpos_cum=0;
	size_t wpos_cum2=0, rpos_cum2=0;
	uint64_t scan_mod=0, scan_old=0;
	wpos_cum = soinf->ring_buf.wpos_cum;
	rpos_cum = soinf->ring_buf.rpos_cum;
	wpos_cum2 = soinf->ring_buf.wpos_cum2.load();
	rpos_cum2 = soinf->ring_buf.rpos_cum2.load();
	scan_mod =  soinf->scan_mod;
	scan_old =  soinf->scan_old;
	fprintf(stderr, "INFO sock_info, fd=%d peer_fd=%d me   rpos_cum=%zu wpos_cum=%zu    DELTA=%zu (atomic %zu %zu    %zu), scan mod/old=%zu/%zu\n",
		fd, peer_fd,
		rpos_cum, wpos_cum, wpos_cum - rpos_cum,
		rpos_cum2, wpos_cum2, wpos_cum2 - rpos_cum2,
		scan_mod, scan_old);
	fflush(stderr);
	sock_info *soinf_peer = nullptr;
	/* vsaj za tcp, bi to zdaj ze moral biti povezano*/
	//int peer_fd = soinf->peer_fd;
	soinf_peer = sol_find(soinf->peer_fd);
	if(!soinf_peer) {
		fprintf(stderr, "INFO sock_info, fd=%d peer_fd=%d soinf_peer==NULL\n",
			fd, peer_fd);
		return 0;
	}
	wpos_cum = soinf_peer->ring_buf.wpos_cum;
	rpos_cum = soinf_peer->ring_buf.rpos_cum;
	wpos_cum2 = soinf_peer->ring_buf.wpos_cum2.load();
	rpos_cum2 = soinf_peer->ring_buf.rpos_cum2.load();
	scan_mod =  soinf_peer->scan_mod;
	scan_old =  soinf_peer->scan_old;
	fprintf(stderr, "INFO sock_info, fd=%d peer_fd=%d peer rpos_cum=%zu wpos_cum=%zu    DELTA=%zu (atomic %zu %zu    %zu), scan mod/old=%zu/%zu\n",
		fd, peer_fd,
		rpos_cum, wpos_cum, wpos_cum - rpos_cum,
		rpos_cum2, wpos_cum2, wpos_cum2 - rpos_cum2,
		scan_mod, scan_old);
	fflush(stderr);
	return 0;
}

extern "C"
int shutdown(int fd, int how)
{
	int error;

	sock_d("shutdown(fd=%d, how=%d)", fd, how);
	fprintf_pos(stderr, "fd=%d\n", fd);

	sol_print(fd);
    //sol_remove(fd, -1); // ampak, ce je socket shutdown, se se vedno lahko bere iz njega.

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

/*
soreadabledata
so_error
so_state
*/

/*
netperf zapre socket, potem pa proba prebrati se  zadnje ostanke.
nastavi CANTRECVMORE flag, da ne bo netperf.so caka na branje is socketa, ki ga je sam zaprl.
*/
#if IPBYPASS_ENABLED
 	sock_info *soinf = sol_find(fd);
	fprintf_pos(stderr, "fd=%d soinf=%p %d\n", fd, soinf, soinf?soinf->fd:-1);
	if(!soinf) {
		return 0;
	}
	if(!soinf->is_bypass) {
		return 0;
	}
	sock_info *soinf_peer = nullptr;
	/* vsaj za tcp, bi to zdaj ze moral biti povezano*/
	//int peer_fd = soinf->peer_fd;
	soinf_peer = sol_find_peer(soinf->peer_fd, soinf->peer_addr, soinf->peer_port, false); //allow_inaddr_any=false, bo najbrz ok. Saj ce poslusam, nimam pravega peer-a

	set_cantrecvanymore(fd);
	soinf->flags |= SOR_CLOSED;
	fprintf_pos(stderr, "fd=%d soinf=%p      flags=%p 0x%04x\n", fd, soinf, &soinf->flags, (int)soinf->flags);

	if(soinf_peer && soinf_peer->is_bypass) {
		//set_cantrecvanymore(soinf->peer_fd); /// TEGA PA NE MOREM tuji VM narediti...
		soinf_peer->flags |= SOR_CLOSED;
		fprintf_pos(stderr, "fd=%d soinf_peer=%p flags=%p 0x%04x\n", fd, soinf_peer, &soinf_peer->flags, (int)soinf_peer->flags);
		// Now notify peer
		fprintf_pos(stderr, "fd=%d marking peer_fd=%d as modified\n", fd, soinf_peer->fd);
		soinf_peer->modified.store(true, std::memory_order_release);
	}

	// pobrisem svoj soinf - oz to sele kasneje, ker branje is shutdown-ed socket je veljavno.
	//sol_remove(fd, -1); // ampak, ce je socket shutdown, se se vedno lahko bere iz njega.
	// soinf_peer naj pobrise lastnik, v threadu za skeniranje modified flag.
#endif
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

#if IPBYPASS_ENABLED
	sol_remove_real(s, protocol); // late remove.
	sol_insert(s, protocol);
#endif
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

// v host order
//#define IPV4_TO_UINT32(a,b,c,d) ( (((a&0x000000FF)*256 + (b&0x000000FF))*256 + (c&0x000000FF))*256 + (d&0x000000FF) )
#define IPV4_TO_UINT32(a,b,c,d) (ntohl( (a)*0x01000000ul + (b)*0x00010000ul + (c)*0x00000100ul + (d)*0x00000001ul ))

uint32_t get_ipv4_addr() {
	char *str = getenv("OSV_IP");
	uint32_t a=0, b=0, c=0, d=0;
	sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d);
	fprintf_pos(stderr, "IP=%s == %d.%d.%d.%d\n", str, a, b, c, d);
	return IPV4_TO_UINT32(a,b,c,d);
}

void ipbypass_setup() {
#if IPBYPASS_ENABLED == 0
	fprintf_pos(stderr, "SKIP ipbypass_setup\n", "");
	return;
#endif

	fprintf_pos(stderr, "TADA...\n", "");
	//sleep(1);
	my_ip_addr = get_ipv4_addr();
	my_owner_id = ipv4_addr_to_id(my_ip_addr);

	// so_list je skupna za vse VM . NE SME VSAKA VM DOBITI SVOJE z ivshmem_get/at !!!
	/*
	int shmid = ivshmem_get_tag(sizeof(sock_info* [SOCK_INFO_LIST_LEN]), "some-tag");
	if (shmid != -1) {
	    so_list = (sock_info* (*)[SOCK_INFO_LIST_LEN]) ivshmem_at(shmid);
	}*/
	so_list = (sock_info* (*)[SOCK_INFO_LIST_LEN]) get_layout_ivm___so_list();

	// NE, to sme samo "prva" VM. memset((void*)so_list, 0x00, sizeof(*so_list));
	sock_info::unsafe_remove_all_my();

	socket_func = socket;
	// za debug, naj ima 2nd VM druge fd-je
	if (my_owner_id == 91) {
		for (int ii=0; ii<10; ii++) {
			fopen("/", "r");
		}
	}

	pthread_t pthread;
	void* args = NULL;
	pthread_create(&pthread, NULL, bypass_scanner, args);
	pthread_setname_np(pthread, "bypass_scanner");
	//void* retval;
	//pthread_join(pthread, &retval);
}
