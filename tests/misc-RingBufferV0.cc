/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

//
// Instructions: run this test with 4 vcpus
//
#include <cstdlib>
#include <ctime>
#include <osv/sched.hh>
#include <arch.hh>
#include <osv/clock.hh>
#include <osv/debug.hh>
#include <lockfree/ring_buffer.hh>
#include <osv/ring_buffer_v0.hh>
#include <stdint.h>

//
// Create 2 threads on different CPUs which perform concurrent push/pop
// Testing spsc ring
//
#define TEST_DATA_TYPE int

#define BUF_SIZE (1LL* 1024*1024*4)
#define CHUNK_SIZE (1LL* 1024*32)
#define BYTES_TO_PROCESS (1LL*1000*1000*1000 * 100)

template<unsigned SizeMax>
class MyDT_tmpl {
public:
    union {
        int val;
        char dummy[SizeMax];
    } uu;
public:
    int& value() { return uu.val; }
};

typedef MyDT_tmpl<4> MyDT_int;
typedef MyDT_tmpl<1024*1> MyDT_1k;
typedef MyDT_tmpl<1024*32> MyDT_32k;

template<typename RingBuf, typename MyDT = MyDT_int>
class test_spsc_ring_buffer {
public:

    static const int max_random = 25;
    static const u64 elements_to_process = 3000000*100;//00;

    bool run()
    {
        assert (sched::cpus.size() >= 2);

        _ring.alloc(BUF_SIZE); // v bistvu samo za RingBufferV0

        sched::thread * thread1 = sched::thread::make([&] { thread_push(0); },
            sched::thread::attr().pin(sched::cpus[0]));
        sched::thread * thread2 = sched::thread::make([&] { thread_pop(1); },
            sched::thread::attr().pin(sched::cpus[1]));

        thread1->start();
        thread2->start();

        thread1->join();
        thread2->join();

        delete thread1;
        delete thread2;

        bool success = true;
        debug("Results:\n");
        for (int i=0; i < max_random; i++) {
            unsigned pushed = _stats[0][i];
            unsigned popped = _stats[1][i];

            //debug("    value=%-08d pushed=%-08d popped=%-08d\n", i, pushed, popped);

            if (pushed != popped) {
                success = false;
            }
        }

        return success;
    }

private:

    RingBuf _ring;

    int _stats[2][max_random] = {};

    void thread_push(int cpu_id)
    {
        std::srand(std::time(0));
        MyDT element = *new(MyDT);
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            element.value() = std::rand() % max_random;
            //debug("push-a ctr=%d, val=%x %x %d len=%d\n", ctr, &element, &(element.value()), element.value(), sizeof(MyDT));
            // todo - partial read/write
            while (sizeof(element) != _ring.push(&element, sizeof(MyDT))) {
                //debug("push DELAY ctr=%d\n", (int)ctr);
            }
            //debug("push-b ctr=%d, val=%d\n", ctr, element.value());
            _stats[cpu_id][element.value()]++;
        }
    }

    void thread_pop(int cpu_id)
    {
        std::srand(std::time(0));
        MyDT element = *new(MyDT);
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            element.value() = 0;
            while (sizeof(element) != _ring.pop(&element, sizeof(MyDT))) {
                //debug("pop DELAY ctr=%d\n", (int)ctr);
            }
            //debug("pop-b  ctr=%d, val=%x %x %d len=%d\n", ctr, &element, &(element.value()), element.value(), sizeof(MyDT));
            _stats[cpu_id][element.value()]++;
        }
    }
};

char data0[CHUNK_SIZE], data1[CHUNK_SIZE];

template<typename RingBuf>
class test_1th {
public:

    static const int max_random = 25;
    //static const u64 bytes_to_process = 30000000000;

    bool run()
    {
        _ring.alloc(BUF_SIZE);
        assert (sched::cpus.size() >= 2);

        sched::thread * thread1 = sched::thread::make([&] { thread_push_pop(0); },
            sched::thread::attr().pin(sched::cpus[0]));
        thread1->start();
        thread1->join();
        delete thread1;

        bool success = true;
        debug("Results:\n");

        return success;
    }

private:

    RingBuf _ring;

    void thread_push_pop(int cpu_id)
    {
        std::srand(std::time(0));
        size_t len0, len1;
        for (u64 ctr=0; ctr < BYTES_TO_PROCESS; ctr+=CHUNK_SIZE)
        {
            if ((ctr % (CHUNK_SIZE * 1000*10)) == 0) {
                //debug("cnt =%llu\n", ctr);
            }
            len0 = _ring.push(data0, CHUNK_SIZE);
            len1 = _ring.pop(data1, CHUNK_SIZE, nullptr);
            assert(len0 == CHUNK_SIZE);
            assert(len1 == CHUNK_SIZE);
        }
    }

};

template<typename RingBuf, typename MyDT = MyDT_int>
class test_2th_nocheck {
public:

    static const u64 elements_to_process = 3000000*100;//00;

    bool run()
    {
        assert (sched::cpus.size() >= 2);

        _ring.alloc(BUF_SIZE); // v bistvu samo za RingBufferV0

        sched::thread * thread1 = sched::thread::make([&] { thread_push(0); },
            sched::thread::attr().pin(sched::cpus[0]));
        sched::thread * thread2 = sched::thread::make([&] { thread_pop(1); },
            sched::thread::attr().pin(sched::cpus[1]));

        thread1->start();
        thread2->start();

        thread1->join();
        thread2->join();

        delete thread1;
        delete thread2;

        return true;
    }

private:

    RingBuf _ring;

    void thread_push(int cpu_id)
    {
        std::srand(std::time(0));
        MyDT element = *new(MyDT);
        element.value() = std::rand();
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            //debug("push-a ctr=%d, val=%x %x %d len=%d\n", ctr, &element, &(element.value()), element.value(), sizeof(MyDT));
            // todo - partial read/write
            while (sizeof(element) != _ring.push(&element, sizeof(MyDT))) {
                //debug("push DELAY ctr=%d\n", (int)ctr);
            }
            //debug("push-b ctr=%d, val=%d\n", ctr, element.value());
        }
    }

    void thread_pop(int cpu_id)
    {
        MyDT element = *new(MyDT);
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            while (sizeof(element) != _ring.pop(&element, sizeof(MyDT))) {
                //debug("pop DELAY ctr=%d\n", (int)ctr);
            }
            //debug("pop-b  ctr=%d, val=%x %x %d len=%d\n", ctr, &element, &(element.value()), element.value(), sizeof(MyDT));
        }
    }
};

s64 nanotime() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>
                (osv::clock::wall::now().time_since_epoch()).count();
}

template <typename BufferType, typename MyDT>
int run_test_2th_func(const char bt_name[], const char dt_name[], const char desc[])
{
    s64 beg, end;
    bool rc = true;
#if RING_BUFFER_USE_ATOMIC
    debug("\n");
    debug("[~] Testing spsc test_spsc_ring_buffer<%s, %s>, %s:\n", bt_name, dt_name, desc);
    debug("[~] sizeof(MyDT=%s) = %d\n", dt_name, sizeof(MyDT));
    auto& t1 = *(new test_spsc_ring_buffer<BufferType, MyDT>);
    beg = nanotime();
    rc = t1.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_spsc_ring_buffer<%s, %s> passed:\n", bt_name, dt_name);
        debug("[+] duration: %.6fs\n", dT);
        // There is no *2 in the "elements_to_process" part.
        double throughput = (double)(test_spsc_ring_buffer<BufferType>::elements_to_process)/dT;
        debug("[+] throughput: %.3f Mops/s\n", throughput/1e6);
        debug("[+] latency: %.3f ns\n", 1e9/throughput);
    } else {
        debug("[-] spsc test %s,%s failed\n", bt_name, dt_name);
    }
#endif
    return rc;
}
#define run_test_2th(BufferType, DataType, desc) run_test_2th_func<BufferType, DataType>(#BufferType, #DataType, desc)

template <typename BufferType>
int run_test_1th_func(const char bt_name[], const char desc[])
{
    s64 beg, end;
    bool rc = true;
    debug("\n");
    debug("[~] Testing 1 thread test_1th<%s>, %s:\n", bt_name, desc);
    test_1th<RingBufferV0> t1;
    beg = nanotime();
    rc = t1.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] 1 thread test_1th<%s> test passed:\n", bt_name);
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.2f Gbit/s\n", (double)(BYTES_TO_PROCESS *8)/dT /(1024.0*1024*1024));
    } else {
        debug("[-] 1 thread %s test failed\n", bt_name);
    }
    return rc;
}
#define run_test_1th(BufferType, desc) run_test_1th_func<BufferType>(#BufferType, desc)

template <typename BufferType, typename MyDT>
int run_test_2th_nocheck_func(const char bt_name[], const char dt_name[], const char desc[])
{
    s64 beg, end;
    bool rc = true;
#if RING_BUFFER_USE_ATOMIC
    debug("\n");
    debug("[~] Testing spsc test_2th_nocheck<%s, %s>, %s:\n", bt_name, dt_name, desc);
    debug("[~] sizeof(MyDT=%s) = %d\n", dt_name, sizeof(MyDT));
    auto& t1 = *(new test_2th_nocheck<BufferType, MyDT>);
    beg = nanotime();
    rc = t1.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_2th_nocheck<%s, %s> passed:\n", bt_name, dt_name);
        debug("[+] duration: %.6fs\n", dT);
        // There is no *2 in the "elements_to_process" part.
        double throughput = (double)(test_spsc_ring_buffer<BufferType>::elements_to_process)/dT;
        debug("[+] throughput: %.3f Mops/s\n", throughput/1e6);
        debug("[+] latency: %.3f ns\n", 1e9/throughput);
    } else {
        debug("[-] spsc test_2th_nocheck test %s,%s failed\n", bt_name, dt_name);
    }
#endif
    return rc;
}
#define run_test_2th_nocheck(BufferType, DataType, desc) run_test_2th_nocheck_func<BufferType, DataType>(#BufferType, #DataType, desc)

int main(int argc, char **argv)
{
#if 1
    debug("\n/*----------------------------------------------------------------------------*/\n");
    run_test_2th(ring_buffer_spsc<1024*16>, MyDT_int, "16 kB size");
    run_test_2th(ring_buffer_spsc<1024*64>, MyDT_int, " 64 KB size");
    //
    run_test_2th(ring_buffer_spsc<1024*1024*4>, MyDT_int, " 4 MB size");
    run_test_2th(RingBufferV0, MyDT_int, "desc...");
    run_test_2th(RingBuffer_atomic, MyDT_int, "desc...");
#endif
#if 1
    debug("\n/*----------------------------------------------------------------------------*/\n");
    run_test_2th(ring_buffer_spsc<1024*16>, MyDT_1k, "16 kB size");
    run_test_2th(ring_buffer_spsc<1024*64>, MyDT_1k, " 64 KB size");
    //
    run_test_2th(ring_buffer_spsc<1024*1024*4>, MyDT_1k, " 4 MB size");
    run_test_2th(RingBufferV0, MyDT_1k, "desc...");
    run_test_2th(RingBuffer_atomic, MyDT_1k, "desc...");
#endif
#if 1
    debug("\n/*----------------------------------------------------------------------------*/\n");
    //run_test_2th(ring_buffer_spsc<1024*16>, MyDT_32k, "16 kB size");
    //run_test_2th(ring_buffer_spsc<1024*64>, MyDT_32k, " 64 KB size");
    //
    run_test_2th(ring_buffer_spsc<1024*1024*4>, MyDT_32k, " 4 MB size");
    run_test_2th(RingBufferV0, MyDT_32k, "desc...");
    run_test_2th(RingBuffer_atomic, MyDT_32k, "desc...");
#endif

    debug("\n/*******************************************************************************/\n");

#if 1
    debug("\n/*----------------------------------------------------------------------------*/\n");
    //run_test_2th_nocheck(ring_buffer_spsc<1024*16>, MyDT_32k, "16 kB size");
    //run_test_2th_nocheck(ring_buffer_spsc<1024*64>, MyDT_32k, " 64 KB size");
    //
    run_test_2th_nocheck(ring_buffer_spsc<1024*1024*4>, MyDT_32k, " 4 MB size");
    run_test_2th_nocheck(RingBufferV0, MyDT_32k, "desc...");
    run_test_2th_nocheck(RingBuffer_atomic, MyDT_32k, "desc...");
#endif

    debug("\n/*******************************************************************************/\n");

#if 1
    debug("\n/*----------------------------------------------------------------------------*/\n");
    run_test_1th(ring_buffer_spsc<1024*16>, "16 kB size");
    run_test_1th(ring_buffer_spsc<1024*64> , " 64 KB size");
    //
    run_test_1th(ring_buffer_spsc<1024*1024*4>, "4 MB size");
    run_test_1th(RingBufferV0, "desc...");
    run_test_1th(RingBuffer_atomic, "desc...");
#endif

    debug("[+] finished.\n");
    return 0;
}
