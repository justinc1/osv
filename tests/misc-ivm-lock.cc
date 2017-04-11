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
// Create 2 threads on different CPUs which perform lock/unlock
// Testing ivm_lock
//
class test_ivm_lock {
public:

    static const u64 elements_to_process = 3000000;//00;

    bool run()
    {
        assert (sched::cpus.size() >= 2);

        sched::thread * thread1 = sched::thread::make([&] { thread_counter(0); },
            sched::thread::attr().pin(sched::cpus[0]));
        sched::thread * thread2 = sched::thread::make([&] { thread_counter(1); },
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

    ivm_lock _lock;

    u64 _count[2] = {};

    void thread_counter(int cpu_id)
    {
        std::srand(std::time(0));
        for (u64 ctr=0; ctr < elements_to_process; ctr++)
        {
            _lock.lock();
            _count[cpu_id]++;
            _lock.unlock();
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
    debug("[~] Testing ivm_lock:\n");
    test_ivm_lock *t1 = new test_ivm_lock();
    s64 beg = nanotime();
    bool rc = t1->run();
    s64 end = nanotime();
    delete t1;
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] ivm_lock test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        debug("[+] throughput: %.0f ops/s\n", (double)(test_ivm_lock::elements_to_process*2)/dT);
    } else {
        debug("[-] ivm_lock failed\n");
        return 1;
    }

    debug("[+] finished.\n");
    return 0;
}
