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

//
// Create 2 threads on different CPUs which perform concurrent push/pop
// Testing spsc ring
//
#define TEST_DATA_TYPE int
class test_spsc_ring_buffer {
public:

    static const int max_random = 25;
    static const u64 elements_to_process = 300000000;

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

            debug("    value=%-08d pushed=%-08d popped=%-08d\n", i,
                pushed, popped);

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
            _stats[cpu_id][element]++;
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
    debug("[~] Testing spsc ringbuffer:\n");
    test_spsc_ring_buffer t1;
    s64 beg = nanotime();
    bool rc = t1.run();
    s64 end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] spsc test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_spsc_ring_buffer::elements_to_process*2)/dT);
    } else {
        debug("[-] spsc test failed\n");
        return 1;
    }

    debug("[+] finished.\n");
    return 0;
}
