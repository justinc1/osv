
#ifndef __RING_BUFFER_V0_HH__
#define __RING_BUFFER_V0_HH__

#define BYPASS_BUF_SZ (1024*1024*4)

#include <lockfree/ring_buffer.hh>

// SBS_CANTRCVMORE
//#ifndef SBS_CANTRCVMORE
//#define	SBS_CANTRCVMORE		0x0020	/* can't receive more data from peer */
//#endif // SBS_CANTRCVMORE

// sock_info.flags
#define SOR_CLOSED          0x0001
#define SOR_DELETED         0x0002
#define SOR_NONBLOCK        0x0100

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

class RingBufferV0 {
public:
	RingBufferV0();
	~RingBufferV0();
	void alloc(size_t len);
	size_t push(const void* buf, size_t len);
	size_t pop(void* buf, size_t len, short *flags=nullptr);
public:
	size_t available_read();
	size_t available_write();
	size_t push_part(const void* buf, size_t len);
	size_t push_udp(const void* buf, size_t len);
	size_t push_tcp(const void* buf, size_t len);
	size_t pop_part(void* buf, size_t len);
	size_t pop_udp(void* buf, size_t len);
	size_t pop_tcp(void* buf, size_t len, short *flags=nullptr);
public:
	char* data;
	size_t length;
	volatile size_t rpos;
	volatile size_t wpos;
	size_t rpos_cum;
	size_t wpos_cum;
	std::atomic<size_t> wpos_cum2, rpos_cum2;
public:
};

#include <osv/trace.hh>
#include <osv/ipbypass.h>
TIMED_TRACEPOINT(trace_ipby_ringA_push, "tid=%d LINE=%d this=%p len=%d", long, int, void*, unsigned int);
TIMED_TRACEPOINT(trace_ipby_ringA_pop, "tid=%d LINE=%d this=%p len=%d", long, int, void*, unsigned int);

class RingBuffer_atomic : public ring_buffer_spsc<BYPASS_BUF_SZ> {
public:
	RingBuffer_atomic() {
		data = ring_buffer_spsc::get_data();
		wpos_cum = rpos_cum = 0;
		wpos_cum2.store(0);
		rpos_cum2.store(0);
	};
	~RingBuffer_atomic() {
	};
	void alloc(size_t len) {
		assert(len == BYPASS_BUF_SZ);
	};
public:
    void call_ctor()
    {
        // do what ctor does.
        ring_buffer_spsc::call_ctor();

        data = ring_buffer_spsc::get_data();
		wpos_cum = rpos_cum = 0;
		wpos_cum2.store(0);
		rpos_cum2.store(0);
    }

    void call_dtor()
    {

    }

    static RingBuffer_atomic* alloc_ivshmem()
    {
        //_ring = nullptr;
        RingBuffer_atomic *obj;
        int shmid = ivshmem_get(sizeof(RingBuffer_atomic));
        if (shmid == -1) {
            return nullptr;
        }
        obj = (RingBuffer_atomic*)(ivshmem_at(shmid));
        if (obj == nullptr) {
            return nullptr;
        }
        obj->call_ctor();
        return obj;
    }

    void free_ivshmem()
    {
        call_dtor();
        ivshmem_dt(this);
    }
public:
	size_t push(const void* buf, size_t len) {
		trace_ipby_ringA_push(gettid(), __LINE__, this, len);
		size_t ret;
		if (len == 0) {
			trace_ipby_ringA_push_err(gettid(), __LINE__, this, len);
			return 0;
		}
		while (0 == (ret = ring_buffer_spsc::push(buf, len))) {
		}
		wpos_cum += ret;
		wpos_cum2 += ret;
		trace_ipby_ringA_push_ret(gettid(), __LINE__, this, ret);
		return ret;
	}
	size_t pop(void* buf, size_t len, short *flags=nullptr) {
		size_t ret;
		trace_ipby_ringA_pop(gettid(), __LINE__, this, len);
		while (0 == (ret = ring_buffer_spsc::pop(buf, len))) {
			if (flags && (*flags & SOR_CLOSED)) {
				// cantrecv is set, socket was closed while reading
				break;
			}
			/*
			Torej tu caka reader.
			Samo ce je writer vpisal, pa reader ne opazi.
			Saj berem kot atomic_int.
			*/
		}
		rpos_cum += ret;
		rpos_cum2 += ret;
		trace_ipby_ringA_pop_ret(gettid(), __LINE__, this, ret);
		if(0) {trace_ipby_ringA_pop_err(gettid(), __LINE__, this, ret);}
		return ret;
	}
public:
	size_t available_read() {
		// size() returns correct value for writer, and maybe incorrect/too small for reader.
		// so reader migth se less data avaliable for reading than actually available
		return size();
	};
	size_t available_write() {
		return BYPASS_BUF_SZ - size();
	};
	bool empty() {
		return ring_buffer_spsc::empty();
	}
	bool empty2() {
		return ring_buffer_spsc::empty2();
	}
public:
	size_t wpos_cum, rpos_cum;
	std::atomic<size_t> wpos_cum2, rpos_cum2;
	char* data;
};

#endif // __RING_BUFFER_VO_HH__
