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
        debug("sizeof(MyDT) = %d\n", sizeof(MyDT));

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
        // delete thread1; tole mi sesuva OSv ????

        bool success = true;
        debug("Results:\n");
        /*for (int i=0; i < max_random; i++) {
            unsigned pushed = _stats[0][i];
            unsigned popped = _stats[1][i];

            debug("    value=%-08d pushed=%-08d popped=%-08d\n", i,
                pushed, popped);

            if (pushed != popped) {
                success = false;
            }
        }*/

        return success;
    }

private:

    RingBuf _ring;

    //int _stats[2][max_random] = {};

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


s64 nanotime() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>
                (osv::clock::wall::now().time_since_epoch()).count();
}

int main(int argc, char **argv)
{
    // Test
    sleep(1);
    fprintf(stderr, "\n");
    s64 beg, end;
    bool rc;
#if 1
#if RING_BUFFER_USE_ATOMIC
    // 16 kB
    debug("\n");
    debug("[~] Testing spsc test_spsc_ring_buffer<ring_buffer_spsc<4096*sizeof(TEST_DATA_TYPE)>>:\n");
    auto& t1 = *(new test_spsc_ring_buffer<ring_buffer_spsc<4096*sizeof(TEST_DATA_TYPE)>>);
    beg = nanotime();
    rc = t1.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_spsc_ring_buffer<ring_buffer_spsc<4096*sizeof(TEST_DATA_TYPE)>> passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer<ring_buffer_spsc<4096*sizeof(TEST_DATA_TYPE)>>::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }
#endif
#endif

#if 1
#if RING_BUFFER_USE_ATOMIC
    // 4 MB
    debug("\n");
    debug("[~] Testing spsc test_spsc_ring_buffer<RingBufferV0>:\n");
    static_assert(4 == sizeof(TEST_DATA_TYPE), "sizeof(TEST_DATA_TYPE) != 4");
    auto& t1c = *(new test_spsc_ring_buffer<RingBufferV0>);
    beg = nanotime();
    rc = t1c.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_spsc_ring_buffer<RingBufferV0> passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer<RingBufferV0>::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }
#endif
#endif

#if 1
#if RING_BUFFER_USE_ATOMIC
    // 4 MB
    debug("\n");
    debug("[~] Testing spsc test_spsc_ring_buffer<RingBuffer_atomic>:\n");
    auto& t1d = *(new test_spsc_ring_buffer<RingBuffer_atomic>);
    beg = nanotime();
    rc = t1d.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_spsc_ring_buffer<RingBuffer_atomic> passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer<RingBuffer_atomic>::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }
#endif
#endif

#if 1
#if RING_BUFFER_USE_ATOMIC
    // 4 MB
    debug("\n");
    debug("[~] Testing spsc test_spsc_ring_buffer<ring_buffer_spsc<1024*1024*sizeof(TEST_DATA_TYPE)>>:\n");
    static_assert(4 == sizeof(TEST_DATA_TYPE), "sizeof(TEST_DATA_TYPE) != 4");
    auto& t1b = *(new test_spsc_ring_buffer<ring_buffer_spsc<1024*1024*sizeof(TEST_DATA_TYPE)>>);
    beg = nanotime();
    rc = t1b.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_spsc_ring_buffer<ring_buffer_spsc<1024*1024*sizeof(TEST_DATA_TYPE)>> passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer<ring_buffer_spsc<1024*1024*sizeof(TEST_DATA_TYPE)>>::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }
#endif
#endif


#if 1
#if RING_BUFFER_USE_ATOMIC
    // 4 MB
    debug("\n");
    debug("[~] Testing spsc test_spsc_ring_buffer<ring_buffer_spsc<64KB>>:\n");
    auto& t1e = *(new test_spsc_ring_buffer<ring_buffer_spsc<1024*64>>);
    beg = nanotime();
    rc = t1e.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test test_spsc_ring_buffer<ring_buffer_spsc<64KB>> passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer<ring_buffer_spsc<1024*64>>::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }
#endif
#endif

debug("\n/*----------------------------------------------------------------------------*/\n");

#if 1
    debug("\n");
    debug("[~] Testing 1 thread RingBufferV0:\n");
    test_1th<RingBufferV0> t2;
    beg = nanotime();
    rc = t2.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] 1 thread RingBufferV0 test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.2f Gbit/s\n", (double)(BYTES_TO_PROCESS *8)/dT /(1024.0*1024*1024));
    } else {
        debug("[-] 1 thread RingBufferV0 test failed\n");
        return 1;
    }
#endif

#if 1
    debug("\n");
    debug("[~] Testing 1 thread RingBuffer_atomic:\n");
    auto& t3 = *(new test_1th<RingBuffer_atomic>);
    beg = nanotime();
    rc = t3.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] 1 thread RingBuffer_atomic test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.2f Gbit/s\n", (double)(BYTES_TO_PROCESS *8)/dT /(1024.0*1024*1024));
    } else {
        debug("[-] 1 thread RingBuffer_atomic test failed\n");
        return 1;
    }
#endif

#if 1
    debug("\n");
    debug("[~] Testing 1 thread ring_buffer_spsc<4MB>:\n");
    auto& t4 = *(new test_1th<ring_buffer_spsc<1024*1024*4>>);
    beg = nanotime();
    rc = t4.run();
    end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] 1 thread ring_buffer_spsc<4MB> test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.2f Gbit/s\n", (double)(BYTES_TO_PROCESS *8)/dT /(1024.0*1024*1024));
    } else {
        debug("[-] 1 thread ring_buffer_spsc<4MB> test failed\n");
        return 1;
    }
#endif

#if 1
    debug("\n");
    if (CHUNK_SIZE<1024*64) {
    debug("[~] Testing 1 thread ring_buffer_spsc<64KB>:\n");
        auto& t5 = *(new test_1th<ring_buffer_spsc<1024*64>>);
        beg = nanotime();
        rc = t5.run();
        end = nanotime();
        if (rc) {
            double dT = (double)(end-beg)/1000000000.0;
            debug("[+] 1 thread ring_buffer_spsc<64KB> test passed:\n");
            debug("[+] duration: %.6fs\n", dT);
            debug("[+] throughput: %.2f Gbit/s\n", (double)(BYTES_TO_PROCESS *8)/dT /(1024.0*1024*1024));
        } else {
            debug("[-] 1 thread ring_buffer_spsc<256KB> test failed\n");
            return 1;
        }
    }
    else {
        debug("[~] SKIP 1 thread ring_buffer_spsc<64KB>, CHUNK_SIZE=%d >= 64KB:\n", CHUNK_SIZE);
    }
#endif

    debug("[+] finished.\n");
    return 0;
}
