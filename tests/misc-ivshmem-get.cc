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
#include <drivers/virtio-ivshmem.hh>

//
// Test ivshemem sysV-like api.
// Create 2 threads on different CPUs which perform ivshmem get/delete
//

// ivshmem layout is: GUARD_SIZE + INTERVM_SIZE + GUARD_SIZE + USER_DATA ==
// 4 + 64 + 4 + ? KB 
#define REQUIRED_IVSHMEM_SIZE (1024*1024 * (128)) 

class test_ivshmem_get {
public:

    static const u64 elements_to_process = 1000000;//00;
    static const int alloc_size = 1024*1024*1;
    static const int alloc_segments = 50;

    bool run()
    {
        assert (sched::cpus.size() >= 2);

        sched::thread * thread1 = sched::thread::make([&] { thread_simple(0); },
            sched::thread::attr().pin(sched::cpus[0]));
        sched::thread * thread2 = sched::thread::make([&] { thread_simple(1); },
            sched::thread::attr().pin(sched::cpus[1]));

        thread1->start();
        thread2->start();

        thread1->join();
        thread2->join();

        delete thread1;
        delete thread2;

        bool success = true;
        debug("Results:\n");
        debug("    count = %-08d %-08d", _count[0], _count[1]);
        if (_count[0] != _count[1]) {
            success = false;
        }

        return success;
    }

private:

    u64 _count[2] = {};

    void thread_simple(int cpu_id)
    {
        std::srand(std::time(0));
        int ret;
        int shm_id = -1;
        void *shm_data = nullptr;
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            shm_id = ivshmem_get(alloc_size);
            shm_data = ivshmem_at(shm_id);
            ret = ivshmem_dt(shm_data);
            _count[cpu_id]++;
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
    debug("[~] Testing ivshmem_get/at/dt:\n");
    test_ivshmem_get *t1 = new test_ivshmem_get();
    s64 beg = nanotime();
    bool rc = t1->run();
    s64 end = nanotime();
    delete t1;
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] ivm_lock test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_ivshmem_get::elements_to_process*2)/dT);
    } else {
        debug("[-] ivm_lock failed\n");
        return 1;
    }

    debug("[+] finished.\n");
    return 0;
}
