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


#include <osv/ring_buffer_v0.hh>


#if 1
#  undef fprintf_pos
#  define fprintf_pos(...) /**/
#endif
#if 0
#  undef assert
#  define assert(...) /**/
#endif

#include <osv/mutex.h>
#define PUSH_LOCKED 0
#define MEM_BARRIER 
	//asm volatile("" ::: "memory")

#if PUSH_LOCKED
static mutex mtx_push_pop;
#endif

//#define my_memcpy memcpy
#define my_memcpy memmove
//#define my_memcpy repmovsb 
// TODO TRY repmovsb 

bool in_range(size_t val, size_t low, size_t high)
{
	if (high>low) {
		return low <= val && val < high;
	}
	else {
		return low <= val || val < high;
	}
}

RingBufferV0::RingBufferV0()
{
	data = nullptr;
	fprintf_pos(stderr, "RingBufferV0::RingBufferV0 this=%p data=%p at %p \n", this, data, &data);
	length = 0;
	rpos = 0;
	wpos = 0;
	rpos_cum = 0;
	wpos_cum = 0;
	wpos_cum2.store(0);
	rpos_cum2.store(0);
	// da ne bo cakanja na malloc v prvem recvfrom. Ce je sploh problem cakanje na malloc - mogoce samo IP-layer malo steka :/
	//alloc(BYPASS_BUF_SZ);
}

RingBufferV0::~RingBufferV0()
{
	if (data) {
		fprintf_pos(stderr, "RingBufferV0::~RingBufferV0 this=%p free-ing data=%p at %p \n", this, data, &data);
		free(data);
	}
	data = nullptr;
	length = 0;
	rpos = 0;
	wpos = 0;
}

void RingBufferV0::alloc(size_t len)
{
	assert(data == nullptr);
	assert(length == 0);
	data = (char*)malloc(len);
	if (!data)
		return;
	fprintf_pos(stderr, "RingBufferV0::alloc this=%p data=%p at %p len=%d\n", this, data, &data, len);
	memset(data, 0x11, len);
	length = len;
	rpos = 0;
	wpos = 0;
}

size_t RingBufferV0::available_read() {
	size_t len;
#if PUSH_LOCKED
	SCOPE_LOCK(mtx_push_pop);
#endif
	// naredi local kopijo
	size_t loc_rpos, loc_wpos;
	loc_rpos = rpos;
	loc_wpos = wpos;

	assert(0 <= loc_rpos);
	assert(loc_rpos < length);
	assert(0 <= loc_wpos);
	assert(loc_wpos < length);

	MEM_BARRIER;
	// test:
	// rpos=0, wpos=0
	// rpos=0, wpos=length
	// rpos=70, wpos=80
	// rpos=90, wpos=10, length=100
	//
	// size_t is unsigned
	// rpos==wpos - poseben primer.
	// Npr rpos=0, wpos=0; lahko je zacetno stanje, in available_read==0.
	// Ali pa je write ze cel buffer napolnil, enkrat padel okrog, in available_read==lenght.
	// Torej prepovem stanje, ko je buffer povsem poln; rpos==wpos pomeni, da je buffer povsem prazen.
	//
	// ze v tem if (rpos<wpos) se lahko en ali drugi spremeni do dejanskega odstevanja.
	if (loc_rpos <= loc_wpos) {
		// rpos=70, wpos=80
		len = loc_wpos - loc_rpos;
	}
	else {
		// rpos=90, wpos=10, length=100
		len = (length+loc_wpos) - loc_rpos;
	}
	assert(0 <= len);
	assert(len < length); // len==length je prepovedan (povsem poln buffer)
	return len;
}

size_t RingBufferV0::available_write() {
	size_t len = length - available_read();
	assert(0 <= len);
	assert(len <= length); // to se dovolim. Ampak writer naj ne proba do konca napolniti.
	return len;
}

// TODO push messages one-by-one
// limit max size - 2 kB
size_t RingBufferV0::push_part(const void* buf, size_t len)
{
	size_t wpos2, len1, len2;
	size_t writable_len;

	assert(0 <= rpos);
	assert(rpos < length);
	assert(0 <= wpos);
	assert(wpos < length);
	assert(rpos_cum <= wpos_cum);
	assert(wpos_cum - rpos_cum <= length); //**//

	MEM_BARRIER;
	writable_len = available_write(); 
	assert(len < writable_len); // < - povsem poln buffer je prepovedan
	assert(len <= length);
	assert(0 <= len);

	if (len > writable_len) {
		// drop packet
		return 0;
	}
	wpos2 = wpos + len;
	if (wpos2 < length) {
		my_memcpy(data + wpos, buf, len);
		// mbarrier
		wpos = wpos2;
	}
	else {
		len1 = length - wpos;
		len2 = len - len1;
		assert(len1 + len2 == len);
		assert(len1 < length);
		assert(len2 < length);
		assert(wpos + len1 <= length);
		my_memcpy(data + wpos, buf, len1);
		my_memcpy(data, buf + len1, len2);
		// mbarrier
		wpos = len2;
	}
	wpos_cum += len;
	wpos_cum2 += len;
	MEM_BARRIER;

	assert(0 <= rpos);
	assert(rpos < length);
	assert(0 <= wpos);
	assert(wpos < length);
	assert(rpos_cum <= wpos_cum);
	//assert(wpos_cum - rpos_cum <= length); //* TODO tudi rad crkne *//
	return len;
}
size_t RingBufferV0::push(const void* buf, size_t len)
{
	return push_tcp(buf, len);
}
size_t RingBufferV0::push_tcp(const void* buf, size_t len)
{
	size_t writable_len, len2;
	size_t reserved_space = 10;
	writable_len = 0;
	while (len+reserved_space > writable_len) {
		if(writable_len != 0) { // first loop
			fprintf_pos(stderr, "RingBufferV0::push delay\n", "");
		}

#if PUSH_LOCKED
		WITH_LOCK(mtx_push_pop)
#endif
		{
			writable_len=available_write();
		}
		// drop packet
		//return 0;

		//usleep(1);
	}
#if PUSH_LOCKED
	WITH_LOCK(mtx_push_pop)
#endif
	{
	assert(writable_len <= length);
	assert(0 <= writable_len);
	assert(len <= writable_len);
	assert(0 <= len);

	len2 = push_part(buf, len);

	assert(wpos < length);
	assert(0 <= wpos);
	assert(rpos < length);
	assert(0 <= rpos);
	assert(rpos_cum <= wpos_cum);
	//assert(wpos_cum - rpos_cum <= length); /* XXX tudi ta crkne :/ */
	}

	return len2;
}

#if 0
size_t RingBufferV0::push_udp(const void* buf, size_t len)
{
	RingMessageHdr hdr;
	while (sizeof(hdr) + len > available_write()) {
		// drop packet
		//return 0;
		fprintf_pos(stderr, "RingBufferV0::push delay\n", "");
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
#endif

size_t RingBufferV0::pop_part(void* buf, size_t len)
{
	size_t rpos2, len1, len2;
	size_t readable_len = 0;

	size_t loc_rpos_cum, loc_wpos_cum;
	size_t loc_rpos, loc_wpos;
	loc_rpos_cum = rpos_cum;
	loc_wpos_cum = wpos_cum;
	loc_rpos = rpos;
	loc_wpos = wpos;
	MEM_BARRIER;

	// samo da so variable uporabljen
	if(0) {
		size_t xx;
		xx = loc_wpos_cum + loc_rpos_cum + loc_wpos + loc_rpos + readable_len;
		printf("blah %d\n", xx);
	}

	readable_len = available_read();
	MEM_BARRIER;
	//
	//assert(loc_rpos_cum + readable_len <= loc_wpos_cum); // wpos/wpos_cum in readable_len se vmes poveca, loc cache pa je enak. ta test je zato slab.
	//assert(rpos_cum + readable_len <= loc_wpos_cum);

	// recimo, da obstaja micena moznost, da writer ze nastavi wpos, ni pa se povecal wpos_cum.
	// potem se mi lahko (oz se zato) zgodi, da je je loc_rpos_cum == loc_wpos_cum, loc_rpos +128kB == loc_wpos_cum, 
	// in spodnji test crkne.
	// XXX mali-delay assert(loc_rpos_cum + readable_len <= wpos_cum);
	// XXX mali-delay assert(rpos_cum + readable_len <= wpos_cum);

	assert(readable_len <= length);
	assert(0 <= readable_len);
	assert(len <= readable_len); /* TODO fix */
	assert(0 <= len);
	assert(len <= length);

	//size_t readable_len = available_read();
	rpos2 = rpos + len;
	if (rpos2 < length) {
		my_memcpy(buf, data + rpos, len);
		// mbarrier
		rpos = rpos2;
	}
	else {
		len1 = length - rpos;
		len2 = len - len1;
		assert(len1 + len2 == len);
		assert(len1 < length);
		assert(len2 < length);
		assert(rpos + len1 <= length);
		my_memcpy(buf, data + rpos, len1);
		my_memcpy(buf + len1, data, len2);
		// mbarrier
		rpos = len2;
	}
	rpos_cum += len;
	rpos_cum2 += len;

	MEM_BARRIER;
	assert(wpos < length);
	assert(0 <= wpos);
	assert(rpos < length);
	assert(0 <= rpos);
	assert(rpos_cum == loc_rpos_cum + len);
	// XXX mali-delay assert(rpos_cum <= loc_wpos_cum);
	// XXX ajde, tudi tega ne razumem. assert(loc_wpos_cum - rpos_cum <= length);

	return len;
}

size_t RingBufferV0::pop(void* buf, size_t len, short *so_rcv_state) {
	return pop_tcp(buf, len, so_rcv_state);
}
size_t RingBufferV0::pop_tcp(void* buf, size_t len, short *so_rcv_state)
{
	int cnt = 0;
	size_t readable_len = 0;
	while (readable_len <= 0) {
#if PUSH_LOCKED
		WITH_LOCK(mtx_push_pop)
#endif
		{
			readable_len = available_read();
		}
		if(cnt==0)
			fprintf_pos(stderr, "RingBufferV0::pop delay cnt=%d readable_len=%d wpos=%d rpos=%d\n", cnt, (int)readable_len, wpos, rpos);
		cnt++;
		/*if(cnt==0) {
			// wrap around, writer is slow, or socket was closed in between.
			return 0;
		}*/
		if (so_rcv_state && (*so_rcv_state & SBS_CANTRCVMORE)) {
			// cantrecv is set, socket was closed while reading
			return 0;
		}
		//usleep(1);
	}
		if(cnt>0)
			fprintf_pos(stderr, "RingBufferV0::pop delay cnt=%d readable_len=%d wpos=%d rpos=%d\n", cnt, (int)readable_len, wpos, rpos);
	len = std::min(len, readable_len);
#if PUSH_LOCKED
	WITH_LOCK(mtx_push_pop)
#endif
	{
		return pop_part(buf, len);
	}
}

#if 0
size_t RingBufferV0::pop_udp(void* buf, size_t len)
{
	RingMessageHdr hdr;
	size_t readable_len;
	/* if (sizeof(hdr) + 0 > readable_len) {
		// no packet
		return 0;
	} */
	//fprintf(stderr, "RingBufferV0::pop\n");
	int cnt = 0;
	// (sizeof(hdr)+1 -> assume all mesages are at least 1 B long.
	// otehrwise, the assert(sizeof(hdr) + hdr.length <= readable_len); fails
	while ((sizeof(hdr) + 1) > (readable_len = available_read())) {
		if(cnt==0)
			fprintf_pos(stderr, "RingBufferV0::pop delay cnt=%d readable_len=%d wpos=%d rpos=%d\n", cnt, (int)readable_len, wpos, rpos);
		cnt++;
		//usleep(1);
	}
		if(cnt>0)
			fprintf_pos(stderr, "RingBufferV0::pop delay cnt=%d readable_len=%d wpos=%d rpos=%d\n", cnt, (int)readable_len, wpos, rpos);
	//fprintf(stderr, "RingBuffer::pop-ing len=%d , rpos=%d, wpos=%d\n", len, rpos, wpos);
	pop_part(&hdr, sizeof(hdr));
	assert(sizeof(hdr) + hdr.length <= readable_len);
	len = pop_part(buf, hdr.length);
	assert(len == hdr.length);
	//fprintf(stderr, "RingBufferV0::pop-ed  len=%d , rpos=%d, wpos=%d\n", len, rpos, wpos);
	return hdr.length;
}
#endif

/*--------------------------------------------------------------------------*/


#include <lockfree/ring_buffer.hh>

//class sock_info {
