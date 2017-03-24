
#ifndef __RING_BUFFER_V0_HH__
#define __RING_BUFFER_V0_HH__

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

#endif // __RING_BUFFER_VO_HH__
