
#ifndef __RING_BUFFER_V0_HH__
#define __RING_BUFFER_V0_HH__

#define BYPASS_BUF_SZ (1024*1024*4)

#include <lockfree/ring_buffer.hh>

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
	size_t pop(void* buf, size_t len, short *so_rcv_state=nullptr);
public:
	size_t available_read();
	size_t available_write();
	size_t push_part(const void* buf, size_t len);
	size_t push_udp(const void* buf, size_t len);
	size_t push_tcp(const void* buf, size_t len);
	size_t pop_part(void* buf, size_t len);
	size_t pop_udp(void* buf, size_t len);
	size_t pop_tcp(void* buf, size_t len, short *so_rcv_state=nullptr);
public:
	char* data;
	size_t length;
	volatile size_t rpos;
	volatile size_t wpos;
	size_t rpos_cum;
	size_t wpos_cum;
public:
};

class RingBuffer_atomic : public ring_buffer_spsc<BYPASS_BUF_SZ> {
public:
	RingBuffer_atomic() {
		data = ring_buffer_spsc::get_data();
		wpos_cum = rpos_cum = 0;
		wpos_cum2.store(0);
		rpos_cum2.store(0);
	};
	~RingBuffer_atomic();
	void alloc(size_t len) {
		assert(len == BYPASS_BUF_SZ);
	};
	size_t push(const void* buf, size_t len) {
		size_t ret;
		char* buf2 = (char*)buf;
		size_t len2 = len;
		while (len2 != 0) {
			ret = ring_buffer_spsc::push(buf2, len2);
			len2 -= ret;
			buf2 += ret;
		}
		wpos_cum += len;
		wpos_cum2 += len;
		return len;
	}
	size_t pop(void* buf, size_t len, short *so_rcv_state=nullptr) {
		size_t ret;
		char* buf2 = (char*)buf;
		size_t len2 = len;
		while (len2 != 0) {
			ret = ring_buffer_spsc::pop(buf2, len2);
			len2 -= ret;
			buf2 += ret;
			if (so_rcv_state && (*so_rcv_state & SBS_CANTRCVMORE)) {
				// cantrecv is set, socket was closed while reading
				break;
			}
		}
		rpos_cum += len-len2;
		rpos_cum2 += len-len2;
		return len-len2;
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
public:
	size_t wpos_cum, rpos_cum;
	std::atomic<size_t> wpos_cum2, rpos_cum2;
	char* data;
};

#endif // __RING_BUFFER_VO_HH__
