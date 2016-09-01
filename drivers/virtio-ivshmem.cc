/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include "drivers/virtio-ivshmem.hh"

#include <map>
#include <lockfree/mutex.hh>
#include <stdint.h>
#include <stdlib.h>
#include <atomic>

using namespace std;

#define debugf_ivshmem(...)  { if(0) { debugf(__VA_ARGS__); }}
//static int virtio_ivshmem_read(void *buf, int size);

// sudo ./scripts/run.py -V -n -v --pass-args '--device ivshmem,shm=ivshmem,size=1M' -e '/cli/cli.soXX'

static virtio::ivshmem* s_ivshmem = NULL;

namespace virtio {
ivshmem::ivshmem(pci::device& pci_dev)
    : virtio_driver(pci_dev)
    , _irq(pci_dev, [&] { return ack_irq(); }, [&] { handle_irq(); })
{
    add_dev_status(VIRTIO_CONFIG_S_DRIVER_OK);
    // assume we have only ivshmem device
    assert(s_ivshmem == nullptr);
    s_ivshmem = this;

    pci::bar *bar;
    bar = pci_dev.get_bar(3);
    bar->map();
    _data = bar->get_mmio();
    _size = bar->read_bar_size();

#if 0
#define OFFSET (1024*64)
    dump_config();
    fprintf(stderr, "ivshmem pci_dev dump_config\n");
    pci_dev.dump_config();
    fprintf(stderr, "ivshmem pci_dev dump_config DONE\n");

    int ii;
    size_t sz;
    for (ii=0; ii<6; ii++) {
        bar = pci_dev.get_bar(ii);
        fprintf(stderr, "DBG ivshmem bar[%d]=%p\n", ii, bar);
        if(bar) {
            sz = bar->read_bar_size();
            fprintf(stderr, "DBG ivshmem bar[%d] sz=%lu addr64=%p addr_mmio=%p\n", ii, sz, bar->get_addr64(), bar->get_mmio());
        }
    }
    bar = pci_dev.get_bar(3);
    sz = bar->read_bar_size();

    // char pch = (char*) mmio_map(0xfe000000, sz); // Is not OK, it works only up to 8 MB large
    volatile char* pch;
    pch = reinterpret_cast<volatile char*>(bar->get_mmio());
    fprintf(stderr, "DBG ivshmem DUMP pch = %p\n", pch);
    fprintf(stderr, "DBG ivshmem DUMP-string '%s'\n", pch+OFFSET);

    char ch;
    if(pch) {
        fprintf(stderr, "DBG ivshmem DUMP ");
        for (ii=0; ii<16; ii++) {
            ch = pch[ii+OFFSET];
            ch = bar->readb(ii+OFFSET);
            fprintf(stderr, "%c", ch);
        }
        fprintf(stderr, " dump DONE\n");
    }
    if (1) {
        // will be left for next VM run
        /*bar->writeb(OFFSET+0, 'A');
        bar->writeb(OFFSET+1, 'B');
        bar->writeb(OFFSET+2, 'C');
        bar->writeb(OFFSET+3, 'D');*/
        /*
        *reinterpret_cast<volatile u8*>(bar->get_mmio() + OFFSET+0) = 'x';
        *reinterpret_cast<volatile u8*>(bar->get_mmio() + OFFSET+1) = '1';
        *reinterpret_cast<volatile u8*>(bar->get_mmio() + OFFSET+2) = '2';
        *reinterpret_cast<volatile u8*>(bar->get_mmio() + OFFSET+3) = '3';
        */
        pch[0+OFFSET] = 'a';
        pch[1+OFFSET] = 'b';
        pch[2+OFFSET] = 'c';
        pch[3+OFFSET] = 'd';
    }
    fprintf(stderr, "DBG ivshmem DUMP-string2 '%s'\n", pch+OFFSET);
#endif
}

ivshmem::~ivshmem()
{
}

void ivshmem::handle_irq()
{
}

bool ivshmem::ack_irq()
{
    return virtio_conf_readb(VIRTIO_PCI_ISR);
}

hw_driver* ivshmem::probe(hw_device* dev)
{
    return virtio::probe<ivshmem, VIRTIO_IVSHMEM_DEVICE_ID>(dev);
}

volatile void* ivshmem::get_data()
{
    return _data;
}
size_t ivshmem::get_size()
{
    return _size;
}

}


class ivshmem_segment {
public:
    volatile void* data;
    size_t size;
    int ref_count;
    //bool delete_flag;

    ivshmem_segment();
    bool intersect(volatile void* data0, size_t size0);
};

ivshmem_segment::ivshmem_segment()
{
    data = nullptr;
    size = 0;
    ref_count = 0;
    //delete_flag = false;
}

bool ivshmem_segment::intersect(volatile void* data0, size_t size0)
{
    /*
    To not intersect, data0 and (data0+size0) have to both smaller
    or both larger than data2, (data2+size2).
    E.g on same side of [data2, data2+size2) interval
    */
    if (data0+size0 <= data) {
        return false;
    }
    else if (data0 >= data+size) {
        return false;
    }
    else {
        return true;
    }
}

uint64_t s_my_owner_id = 0;

class ivm_lock {
public:
    ivm_lock();
    ~ivm_lock();
    void lock();
    void unlock();
public:
    atomic<uint64_t> owner; // inter-vm unique ID. How to get such value? MAC, IP, uuid, random?
};

ivm_lock::ivm_lock() {
}

ivm_lock::~ivm_lock() {
    if (owner != 0 && owner == s_my_owner_id) {
        debugf_ivshmem("IVSHMEM BUG ivm_lock destructed while lock is held by us!!\n");
        unlock();
    }
}

void ivm_lock::lock() {
    auto expected = s_my_owner_id*0, desired = s_my_owner_id;
    int loop_cnt = 0;
    bool acquired;
    while(false == (acquired = owner.compare_exchange_weak(expected, desired))) {
        loop_cnt++;
        sleep(0);
    }
    debugf_ivshmem("IVSHMEM lock owner=%p loop_cnt=%d\n", owner.load(), loop_cnt);
}

void ivm_lock::unlock() {
    assert(owner != 0 && owner == s_my_owner_id);
    auto expected = s_my_owner_id, desired = s_my_owner_id*0;
    int loop_cnt = 0;
    bool acquired;
    while(false == (acquired = owner.compare_exchange_weak(expected, desired))) {
        loop_cnt++;
        sleep(0);
    }
    debugf_ivshmem("IVSHMEM unlock owner=%p loop_cnt=%d\n", owner.load(), loop_cnt);
}


static std::map<int, ivshmem_segment> s_segments;
static lockfree::mutex ivshmem_mutex;

extern "C" {

//#define PAGE_SIZE 4096ull
#define PAGE_MASK (PAGE_SIZE-1)

/* internal check */
static void ivshmem_check() {
    // ivshmem_mutex already locked
    if (s_ivshmem == nullptr) {
        return;
    }

    // no overlap is allowed
    for (auto it1=s_segments.begin(); it1!=s_segments.end(); ++it1) {
        auto data1 = it1->second.data;
        auto size1 = it1->second.size;
        for (auto it2=s_segments.begin(); it2!=s_segments.end(); ++it2) {
            if (it1 == it2)
                continue;
            assert(!it2->second.intersect(data1, size1));
        }
    }

    // TODO add and check guard pages
}

/*
The 'allocator' used is 'get first large enough block'. So nothing to prevent fragmentation.
Good enoughf for current use.
*/
int ivshmem_get(size_t size) {
    SCOPE_LOCK(ivshmem_mutex);
    ivshmem_check();
    debugf_ivshmem("IVSHMEM get size=%d=%p ...\n", size, size);
    size = (size + PAGE_SIZE - 1) & ~PAGE_MASK;

    if (s_ivshmem == nullptr) {
        errno = ENOMEM;
        return -1;
    }
    if (size > s_ivshmem->get_size()) {
        errno = ENOMEM;
        return -1;
    }

    // search for free piece of mem
    volatile void* data = s_ivshmem->get_data(); // Candidate used for first segment
    for (auto it1=s_segments.begin(); it1!=s_segments.end(); ++it1) {
        auto data1 = it1->second.data;
        auto size1 = it1->second.size;
        data = data1 + size1; // Candidate for to-be-allocated area, next byte after it1
        for (auto it2=s_segments.begin(); it2!=s_segments.end(); ++it2) {
            if(it2->second.intersect(data, size)) {
                data = nullptr; // mark candidate as not-usable 
                break;
            }
        }
        if (data) {
            // Candidate does not intersect with existing segments.
            // Now check if it is withinn ivshmem (not beyon endd of ivshmem)
            assert(s_ivshmem->get_data() <= data);
            if (data+size <= s_ivshmem->get_data()+s_ivshmem->get_size()) {
                // Candidate is OK
                break;
            }
        }
    }
    if (!data) {
        // no free space
        errno = ENOMEM;
        return -1;
    }
    // acceptable candidate found
    int id;
    if (s_segments.size() == 0) {
        id = 0;
    }
    else {
        id = s_segments.rbegin()->first + 1;
    }
    ivshmem_segment iseg;
    iseg.data = data;
    iseg.size = size;
    s_segments[id] = iseg;
    debugf_ivshmem("IVSHMEM get id=%d data=%p size=%d=%p\n", id, data, size, size);
    return id;
}

volatile void* ivshmem_at(int id) {
    SCOPE_LOCK(ivshmem_mutex);
    ivshmem_check();
    auto it = s_segments.find(id);
    if (it == s_segments.end()) {
        debugf_ivshmem("IVSHMEM at id=%d not found\n", id);
        errno = EINVAL;
        return (void*) (-1);
    }
    it->second.ref_count++;
    debugf_ivshmem("IVSHMEM at id=%d data=%p size=%d=%p ref_count=%d\n", id, it->second.data, it->second.size, it->second.size, it->second.ref_count);
    return it->second.data;
}

int ivshmem_dt(volatile void* data) {
    SCOPE_LOCK(ivshmem_mutex);
    ivshmem_check();
    for (auto it=s_segments.begin(); it!=s_segments.end(); ++it) {
        if(it->second.data == data) {
            it->second.ref_count--;
            debugf_ivshmem("IVSHMEM dt id=%d data=%p size=%d=%p ref_count=%d\n", it->first, it->second.data, it->second.size, it->second.size, it->second.ref_count);
            if (it->second.ref_count == 0) {
                debugf_ivshmem("IVSHMEM dt id=%d removed\n", it->first);
                s_segments.erase(it);
            }
            return 0;
        }
    }
    // segment not found
    errno = EINVAL;
    return -1;
}

} // extern "C"
