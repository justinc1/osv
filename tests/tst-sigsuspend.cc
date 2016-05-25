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

std::atomic<int> siguser1_received { 0 };
std::atomic<int> siguser2_received { 0 };
void handler1(int sig) {
    printf("Siguser1 handler received signal %d\n", sig);
    siguser1_received += 1;
}
void handler2(int sig) {
    printf("Siguser2 handler received signal %d\n", sig);
    siguser2_received += 1;
}

int main(int ac, char** av)
{
    int sig;
    auto sr = signal(SIGUSR1, handler1);
    assert(sr != SIG_ERR);
    sr = signal(SIGUSR2, handler2);
    assert(sr != SIG_ERR);

    sigset_t set, old_set, full_set;
    sigfillset(&full_set);

    sigprocmask(SIG_SETMASK, &full_set, &old_set);
    printf("Masked all signals.\n");

    // Start a thread that sends SIGUSR1 and SIGUSR2 to proc 0.
    sigprocmask(SIG_SETMASK, &full_set, nullptr);
    std::thread thread1([&] { kill(0, SIGUSR1); kill(0, SIGUSR2);});
    printf("Test 1: Supend after unblocking SIGUSR1 and SIGUSR2..\n");
    sigfillset(&set);
    sigdelset(&set, SIGUSR2);
    sigsuspend(&set);
    thread1.join();
    assert(siguser1_received == 0 && siguser2_received == 1);
    printf("Verified handler for SIGUSR2 is invoked.\n");

    // Reset proc mask.
    printf("Test 2: Reset proc mask to process SIGUSR1 generated from Test 1\n");
    sigprocmask(SIG_SETMASK, &old_set, nullptr);
    assert(siguser1_received == 1);
    printf("Verified handler for SIGUSR1 is invoked after restoring mask.\n");
    printf ("Done.\n");
    return 0;
}
