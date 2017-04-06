/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

//
// single-producer / single-consumer lockless ring buffer of fixed size.
//
#ifndef __LF_RING_BUFFER_HH__
#define __LF_RING_BUFFER_HH__

#include <atomic>
#include <osv/sched.hh>
#include <arch.hh>
#include <osv/ilog2.hh>
#include <osv/debug.hh>

// #define USE_ATOMIC 0 or 1
#define RING_BUFFER_USE_ATOMIC 0

#define ASSERT(...)
//#define ASSERT(...) assert( __VA_ARGS__ )

#define my_memcpy(dd,ss,ll) memcpy(dd,ss,ll)
//#define my_memcpy(dd,ss,ll) {if(0) memcpy(dd,ss,ll);}

//
// spsc ring of fixed size
// intended to store stream of data (not pointer/reference to elements)
//
template<unsigned MaxSize, unsigned MaxSizeMask = MaxSize - 1>
class ring_buffer_spsc {
public:
    ring_buffer_spsc():
#if RING_BUFFER_USE_ATOMIC
     _begin(0), _end(0)
#else
     _begin2(0), _end2(0)
#endif
    {
        static_assert(is_power_of_two(MaxSize), "size must be a power of two");
    }

    void alloc(size_t len)
    {
        assert(len == MaxSize);
    }

    unsigned push(const void* buf, unsigned len)
    {
#if RING_BUFFER_USE_ATOMIC
        unsigned end = _end.load(std::memory_order_relaxed);
#else
        unsigned end = _end2;
#endif
//TODO no atomic var
//TODO no MaxSizeMask
        unsigned sz = size();
        //unsigned end_masked = end & MaxSizeMask;
        unsigned end2;
        //unsigned end2_masked;

        unsigned len2=0, len2_p1=0, len2_p2=0;

        //
        // It's ok to load _begin with relaxed ordering (in the size()) since
        // store to _ring[end & MaxSizeMask] may not be reordered with it due to
        // control dependency (see Documentation/memory-barriers.txt in the
        // Linux tree).
        //
        // allow partial write
        //len2 = std::min(len, MaxSize - sz);
        // forbid partial write
        if (len > (MaxSize - sz))
            return 0;
        len2 = len;

        //new (&_ring[end & MaxSizeMask]) T(std::forward<Args>(args)...);
        //TODO - split into two memcpy calls
        //memcpy(_ring + (end & MaxSizeMask), buf, len);

        end2 = end + len2;
        if ((end2 & ~MaxSizeMask) == (end & ~MaxSizeMask)) {
            // didn't wrap-around, high bits are equal
            my_memcpy(_ring + (end & MaxSizeMask), buf, len2);
        }
        else {
            len2_p1 = MaxSize - (end & MaxSizeMask);
            len2_p2 = len2 - len2_p1;
            ASSERT(len2_p1 + len2_p2 == len2);
            ASSERT(len2_p1 < MaxSize);
            ASSERT(len2_p2 < MaxSize);
            ASSERT((end & MaxSizeMask) + len2_p1 <= MaxSize);
            my_memcpy(_ring + (end & MaxSizeMask), buf, len2_p1);
            my_memcpy(_ring, buf + len2_p1, len2_p2);
        }
        //wpos_cum += len;

#if RING_BUFFER_USE_ATOMIC
        _end.store(end + len2, std::memory_order_release);
#else
        _end2 = end + len2;
#endif

        return len2;
    }

    unsigned pop(void* buf, unsigned len, void* dummy=nullptr)
    {
#if RING_BUFFER_USE_ATOMIC
        unsigned beg = _begin.load(std::memory_order_relaxed);
#else
        unsigned beg = _begin2;
#endif
        unsigned sz = size();
        //unsigned beg_masked = beg & MaxSizeMask;
        unsigned beg2;
        //unsigned beg2_masked;

        unsigned len2=0, len2_p1=0, len2_p2=0;

        // allow partial read
        //len2 = std::min(len, sz);
        // forbid partial read
        if (len > sz)
            return 0;
        len2 = len;

        //element = _ring[beg & MaxSizeMask];
        //TODO - split into two memcpy calls
        //memcpy(buf, _ring + (end & MaxSizeMask), len);

        beg2 = beg + len2;
        if ((beg2 & ~MaxSizeMask) == (beg & ~MaxSizeMask)) {
            // didn't wrap-around, high bits are equal
            my_memcpy(buf, _ring + (beg & MaxSizeMask), len2);
        }
        else {
            len2_p1 = MaxSize - (beg & MaxSizeMask);
            len2_p2 = len2 - len2_p1;
            ASSERT(len2_p1 + len2_p2 == len2);
            ASSERT(len2_p1 < MaxSize);
            ASSERT(len2_p2 < MaxSize);
            ASSERT((beg & MaxSizeMask) + len2_p1 <= MaxSize);
            my_memcpy(buf, _ring + (beg & MaxSizeMask), len2_p1);
            my_memcpy(buf + len2_p1, _ring, len2_p2);
        }
        //rpos_cum += len;
        
        //
        // Use "release" memory order to prevent the reordering of this store
        // and load from the _ring[beg & MaxSizeMask] above.
        //
        // Otherwise there's a possible race when push() already succeeds to
        // trash the element at index "_begin & MaxSizeMask" (when the ring is
        // full) with the new value before the load in this function occurs.
        //
#if RING_BUFFER_USE_ATOMIC
        _begin.store(beg + len2, std::memory_order_release);
#else
        _begin2 = beg + len2;
#endif

        return len2;
    }

    /**
     * Checks if the ring is empty(). May be called by both producer and the
     * consumer.
     *
     * @return TRUE if there are no elements
     */
    bool empty() const {
#if RING_BUFFER_USE_ATOMIC
        unsigned beg = _begin.load(std::memory_order_relaxed);
        unsigned end = _end.load(std::memory_order_acquire);
#else
        unsigned beg = _begin2;
        unsigned end = _end2;
#endif
        return beg == end;
    }

    // DEBUG_ASSERT(!empty(), "calling front() on an empty queue!");

    /**
     * Should be called by the producer. When called by the consumer may
     * someties return a smaller value than the actual elements count.
     *
     * @return the current number of the elements.
     */
    unsigned size() const {
#if RING_BUFFER_USE_ATOMIC
        unsigned end = _end.load(std::memory_order_relaxed);
        unsigned beg = _begin.load(std::memory_order_relaxed);
#else
        unsigned end = _end2;
        unsigned beg = _begin2;
#endif

        return (end - beg);
    }

protected:
    char* get_data() {
        return _ring;
    }

private:
#if RING_BUFFER_USE_ATOMIC
    std::atomic<unsigned> _begin CACHELINE_ALIGNED;
    std::atomic<unsigned> _end CACHELINE_ALIGNED;
#else
    unsigned _begin2, _end2;
#endif
    char _ring[MaxSize];
};

#endif // !__LF_RING_BUFFER_HH__
