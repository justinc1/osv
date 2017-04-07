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

class test_spsc_ring_buffer {
public:

    static const int max_random = 25;
    static const u64 elements_to_process = 3000000*100;//00;

    bool run()
    {
        assert (sched::cpus.size() >= 2);

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

            debug("    value=%-08d pushed=%-08d popped=%-08d\n", i, pushed, popped);

            if (pushed != popped) {
                success = false;
            }
        }

        return success;
    }

private:

    ring_buffer_spsc<4096*sizeof(TEST_DATA_TYPE)> _ring;

    int _stats[2][max_random] = {};

    void thread_push(int cpu_id)
    {
        std::srand(std::time(0));
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            TEST_DATA_TYPE element = std::rand() % max_random;
            // todo - partial read/write
            while (sizeof(element) != _ring.push(&element, sizeof(element)));
                //debug("push DELAY ctr=%d\n", (int)ctr);
            _stats[cpu_id][element]++;
        }
    }

    void thread_pop(int cpu_id)
    {
        std::srand(std::time(0));
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            TEST_DATA_TYPE element = 0;
            while (sizeof(element) != _ring.pop(&element, sizeof(element)));
                //debug("pop DELAY ctr=%d\n", (int)ctr);
            _stats[cpu_id][element]++;
        }
    }
};


#define BUF_SIZE (1LL* 1024*1024*4)
#define CHUNK_SIZE (1LL* 1024*32)
#define BYTES_TO_PROCESS (1LL*1000*1000*1000 * 100)

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
    debug("[~] Testing spsc ringbuffer:\n");
    auto& t1 = *(new test_spsc_ring_buffer);
    beg = nanotime();
    rc = t1.run();
    end = nanotime();
        sleep(1);
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }
#endif
#endif

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
