/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 *
 * Testing on Linux:
 * Step 1: g++ -g -pthread -std=c++11 tests/tst-sigsuspend.cc
 * Step 2: a.out
 *
 * Testing on OSv:
 * Step 1: scripts/build mode=debug image=tests
 * Step 2: scripts/run.py -e /tests/tst-sigsuspend.so
 */


#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>

#include <thread>
#include <atomic>
#include <assert.h>
#include <iostream>

std::atomic<int> siguser_received { 0 };
void handler(int sig) { siguser_received = 1;}

int main(int ac, char** av)
{
    int sig;
    auto sr = signal(SIGUSR1, handler);
    assert(sr != SIG_ERR);

    sigset_t set, old_set, full_set;
    sigfillset(&set);
    sigfillset(&full_set);
    sigdelset(&set, SIGUSR1);
    sigprocmask(SIG_SETMASK, &full_set, &old_set);
    printf("Masked all signals.\n");

    // Start a thread that sends SIGUSR1 to proc 0.
    std::thread thread1([&] { kill(0, SIGUSR1); });
    printf("Supending after unblocking SIGUSR1..\n");
    sigsuspend(&set);
    thread1.join();
    assert(siguser_received == 1);
    printf("Verified handler for SIGUSR1 is invoked.\n");

    // Reset proc mask.
    sigprocmask(SIG_SETMASK, &old_set, nullptr);
    printf ("Done.\n");
    return 0;
}
