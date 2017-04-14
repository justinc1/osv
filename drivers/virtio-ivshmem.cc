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

extern "C" long gettid();

using namespace std;

#define debugf_ivshmem(...)  { if(0) { debugf(__VA_ARGS__); }}
//static int virtio_ivshmem_read(void *buf, int size);

// sudo ./scripts/run.py -V -n -v --pass-args '--device ivshmem,shm=ivshmem,size=1M' -e '/cli/cli.soXX'

static virtio::ivshmem* s_ivshmem = NULL;
extern "C" {
static void intervm_setup();
}

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
    _data = (void*)bar->get_mmio();
    _size = bar->read_bar_size();
    debug("virtio-ivshmem: size=%d at addr=%p\n", _size, _data);

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

    intervm_setup();
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

void* ivshmem::get_data()
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
    int id;
    int ref_count;
    void* data; // TODO change to offset
    size_t size;
    //bool delete_flag;

    ivshmem_segment();
    bool intersect(void* data0, size_t size0) const;
    void remove();
    bool unused() const;
};

void ivshmem_segment::remove()
{
    id = 0; // 0, da je zacetno stanje /dev/shm/ivshmem primerno
    data = nullptr;
    size = 0;
    ref_count = 0;
    //delete_flag = false;
}

ivshmem_segment::ivshmem_segment()
{
    remove();
}

bool ivshmem_segment::unused() const
{
    bool is_unused = id == 0;
    if (is_unused) {
        assert(ref_count == 0);
        assert(data == nullptr);
        assert(size == 0);
    }
    else {
        assert(ref_count >= 0); // ker sele shmat poveca refcount. Po shmget je enak 0.
        assert(data != nullptr);
        assert(size > 0);
    }
    return is_unused;
}

bool ivshmem_segment::intersect(void* data0, size_t size0) const
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

uint64_t ivm_lock::s_owner_id_base = 0;

/*
With ivm_lock placed in ivshemm memory, the ctor is never really called.
So initiallizing lock_flag works only when testing.
Also, if any VM is killed while holding the lock on ivshmem, the lock_flag (and owner id)
will remain set, and ivshmem has to be manually cleared. Should not be a problem, as we
can/should remove the pseudo file bofore each run.
*/
ivm_lock::ivm_lock()
    : lock_flag(false) {
}

ivm_lock::~ivm_lock() {
    if (owner != 0 && owner == owner_id()) {
        debugf_ivshmem("IVSHMEM BUG ivm_lock destructed while lock is held by us!!\n");
        unlock();
    }
}

void ivm_lock::lock() {
    int loop_cnt = 0;
    while(std::atomic_exchange_explicit(&lock_flag, true, std::memory_order_acquire)) {
        loop_cnt++;
    }
    assert(owner == 0);
    owner = owner_id();
    //debugf_ivshmem("IVSHMEM lock owner=%p loop_cnt=%d\n", owner, loop_cnt);
}

void ivm_lock::unlock() {
    if (owner != owner_id()) {
        debugf_ivshmem("IVSHMEM BUG unlock owner=%p != owner_id() =%p\n", owner, owner_id());
    }
    assert(owner != 0 && owner == owner_id());
    //debugf_ivshmem("IVSHMEM unlock owner=%p\n", owner);
    owner = 0;
    std::atomic_store_explicit(&lock_flag, false, std::memory_order_release);
}


//static std::map<int, ivshmem_segment> s_segments;
static ivshmem_segment* ivsegments = nullptr;

extern "C" {

//#define PAGE_SIZE 4096ull
#define PAGE_MASK (PAGE_SIZE-1)
#define GUARD_MAGIC 0xDEADBEEF
#define GUARD_SIZE 4096ull
#define GUARD_SIZE_I32 (GUARD_SIZE/sizeof(uint32_t))
#define INTERVM_SIZE (1024ull*64)
/*
Space reserved for inter-vm sinchronization. Should not be used by "end user".
Should contain mutex to synchronize inter-vm access, and shared map of allocated segments - s_segments.

Layout:
  GUARD_SIZE
  INTERVM_SIZE
  GUARD_SIZE
  [user-allocated segments]
*/

typedef struct {
    uint32_t ivm_guard1[GUARD_SIZE_I32];
    union {
        char __dummy_data[INTERVM_SIZE];
        struct { 
            ivm_lock lock;
            ivshmem_segment ivsegments[IVSHMEM_SEGMENT_LIST_LEN];
            void* so_list[SOCK_INFO_LIST_LEN];

            char ivm_data[INTERVM_SIZE-sizeof(ivm_lock)];
        } ivm2;
    } ivm;
    uint32_t ivm_guard2[GUARD_SIZE_I32];
    char shm_data[1];
} ivshmem_layout;

static ivshmem_layout* get_layout()
{
    if(s_ivshmem == nullptr)
        return nullptr;
    if(s_ivshmem->get_size() < GUARD_SIZE+INTERVM_SIZE+GUARD_SIZE)
        return nullptr;
    ivshmem_layout* layout = (ivshmem_layout*)s_ivshmem->get_data();
    return layout;
}

void* get_layout_ivm___so_list()
{
    ivshmem_layout* layout = get_layout();
    if (!layout)
        return nullptr;
    return layout->ivm.ivm2.so_list;
}

ivshmem_segment* get_layout_ivm___ivsegments()
{
    ivshmem_layout* layout = get_layout();
    if (!layout)
        return nullptr;
    return layout->ivm.ivm2.ivsegments;
}

static void* get_layout_shm_data()
{
    ivshmem_layout* layout = get_layout();
    if (!layout)
        return nullptr;
    return layout->shm_data;
}

static size_t get_layout_shm_size()
{
    ivshmem_layout* layout = get_layout();
    if (!layout)
        return 0;
    return s_ivshmem->get_size() - GUARD_SIZE+INTERVM_SIZE+GUARD_SIZE;
}

static void intervm_setup() {
    uint32_t ii;
    uint32_t *guard;

    /*
    If lock is needed/used for std::atomic, then this cannot work at all :/
    So better check.
    */
    assert(sizeof(ivm_lock::lock_flag) == sizeof(atomic<bool>)); 
    // Initialize owner_id.
    srand((unsigned int) osv::clock::wall::now().time_since_epoch().count());
    for (ii=0; ii<sizeof(ivm_lock::s_owner_id_base)/sizeof(char); ii++) {
        ((char*)(void*)&ivm_lock::s_owner_id_base)[ii] = (char)rand();
    }
    debugf_ivshmem("IVSHMEM ivm_lock::s_owner_id_base=%llu %p\n", ivm_lock::s_owner_id_base, ivm_lock::s_owner_id_base);
    ivsegments = get_layout_ivm___ivsegments();
    debugf_ivshmem("IVSHMEM ivsegments=%p\n", ivsegments);

    // part involving write to the actual shared memory region.
    ivshmem_layout* layout = get_layout();
    if (layout == nullptr)
        return;
    guard = layout->ivm_guard1;
    for (ii=0; ii<GUARD_SIZE_I32; ii++) {
        assert(guard[ii] == 0x00000000 || guard[ii] == GUARD_MAGIC);
        guard[ii] = GUARD_MAGIC;
    }
    guard = layout->ivm_guard2;
    for (ii=0; ii<GUARD_SIZE_I32; ii++) {
        assert(guard[ii] == 0x00000000 || guard[ii] == GUARD_MAGIC);
        guard[ii] = GUARD_MAGIC;
    }

}

/* internal check */
static void ivshmem_check() {
    // ivshmem_mutex already locked
    if (s_ivshmem == nullptr) {
        return;
    }

    // Check guard pages
    uint32_t ii, jj;
    uint32_t *guard;
    ivshmem_layout* layout = get_layout();
    if (layout == nullptr)
        return;
    guard = layout->ivm_guard1;
    for (ii=0; ii<GUARD_SIZE_I32; ii++) {
        assert(guard[ii] == GUARD_MAGIC);
    }
    guard = layout->ivm_guard2;
    for (ii=0; ii<GUARD_SIZE_I32; ii++) {
        assert(guard[ii] == GUARD_MAGIC);
    }

    // no overlap is allowed
    //for (auto it1=s_segments.begin(); it1!=s_segments.end(); ++it1) {
    for (ii=0; ii<IVSHMEM_SEGMENT_LIST_LEN; ii++) {
        ivshmem_segment* ivseg1 = ivsegments + ii;
        if (ivseg1->unused())
            continue;
        auto data1 = ivseg1->data;
        auto size1 = ivseg1->size;
        for (jj=0; jj<IVSHMEM_SEGMENT_LIST_LEN; jj++) {
            if (ii == jj)
                continue;
            ivshmem_segment* ivseg2 = ivsegments + jj;
            if (ivseg2->unused())
                continue;
            assert(!ivseg2->intersect(data1, size1));
        }
    }

}

#define IVM_LOCK_OBJ_LOCK()   { ivshmem_layout* layout = get_layout(); assert(layout != nullptr); layout->ivm.ivm2.lock.lock(); }
#define IVM_LOCK_OBJ_UNLOCK() { ivshmem_layout* layout = get_layout(); assert(layout != nullptr); layout->ivm.ivm2.lock.unlock(); }
/*
Or add local, normal wrapper class to be used with SCOPE_LOCK.
SCOPE_LOCK cannot be used directly on layout->ivm.ivm2.lock, as it creates a temporal object on stack.
But ivm_lock has to be at fixed address, and copy detect error via wrong owner_id (ctor does not set it).
*/

/*
The 'allocator' used is 'get first large enough block'. So nothing to prevent fragmentation.
Good enoughf for current use.
*/
int ivshmem_get(size_t size) {
    ivshmem_layout* layout = get_layout();
    if (layout == nullptr) {
        errno = ENOMEM;
        return -1;
    }
    IVM_LOCK_OBJ_LOCK();

    ivshmem_check();
    debugf_ivshmem("IVSHMEM get size=%d=%p ...\n", size, size);
    size = (size + PAGE_SIZE - 1) & ~PAGE_MASK;

    if (get_layout_shm_data() == nullptr) {
        IVM_LOCK_OBJ_UNLOCK();
        errno = ENOMEM;
        return -1;
    }
    if (size > get_layout_shm_size()) {
        IVM_LOCK_OBJ_UNLOCK();
        errno = ENOMEM;
        return -1;
    }

    // search for free piece of mem
    void* data = get_layout_shm_data(); // Candidate used for first segment
    int ii, jj;
    for (ii=0; ii<IVSHMEM_SEGMENT_LIST_LEN; ii++) {
        ivshmem_segment* ivseg1 = ivsegments + ii;
        if (ivseg1->unused())
            continue;
        auto data1 = ivseg1->data;
        auto size1 = ivseg1->size;
        data = data1 + size1; // Candidate for to-be-allocated area, next byte after it1
        for (jj=0; jj<IVSHMEM_SEGMENT_LIST_LEN; jj++) {
            ivshmem_segment* ivseg2 = ivsegments + jj;
            if (ivseg2->unused())
                continue;
            if (ivseg2->intersect(data, size)) {
                data = nullptr; // mark candidate as not-usable 
                break;
            }
        }
        if (data) {
            // Candidate does not intersect with existing segments.
            // Now check if it is withinn ivshmem (not beyon endd of ivshmem)
            assert(get_layout_shm_data() <= data);
            if (data+size <= get_layout_shm_data()+get_layout_shm_size()) {
                // Candidate is OK
                break;
            }
        }
    }
    if (!data) {
        // no free space
        IVM_LOCK_OBJ_UNLOCK();
        errno = ENOMEM;
        return -1;
    }
    // acceptable candidate found
    int id = 1;
    // find highest unused id
    for (ii=0; ii<IVSHMEM_SEGMENT_LIST_LEN; ii++) {
        ivshmem_segment* ivseg1 = ivsegments + ii;
        if (ivseg1->unused())
            continue;
        id = max(id, ivseg1->id + 1);
    }
    // find free slot
    ivshmem_segment* ivseg1 = nullptr;
    for (ii=0; ii<IVSHMEM_SEGMENT_LIST_LEN; ii++) {
        ivseg1 = ivsegments + ii;
        if (ivsegments[ii].unused()) {
            ivseg1 = ivsegments + ii;
            break;
        }
    }
    if (ivseg1 == nullptr) {
        debugf_ivshmem("IVSHMEM get no free slot to store segment info\n");
        IVM_LOCK_OBJ_UNLOCK();
        errno = ENOMEM;
        return -1;
    }
    ivseg1->id = id;
    ivseg1->data = data;
    ivseg1->size = size;
    ivseg1->ref_count = 0;
    debugf_ivshmem("IVSHMEM get id=%d data=%p size=%d=%p\n", id, data, size, size);
    IVM_LOCK_OBJ_UNLOCK();
    return id;
}

void* ivshmem_at(int id) {
    IVM_LOCK_OBJ_LOCK();
    ivshmem_check();
    ivshmem_segment* ivseg1;
    int ii;
    for (ii=0; ii<IVSHMEM_SEGMENT_LIST_LEN; ii++) {
        ivseg1 = ivsegments + ii;
        if (ivseg1->unused())
            continue;
        if (ivseg1->id == id)
            break;
    }
    if (ii == IVSHMEM_SEGMENT_LIST_LEN) {
        debugf_ivshmem("IVSHMEM at id=%d not found\n", id);
        IVM_LOCK_OBJ_UNLOCK();
        errno = EINVAL;
        return (void*) (-1);
    }
    ivseg1->ref_count++;
    debugf_ivshmem("IVSHMEM at id=%d data=%p size=%d=%p ref_count=%d\n", id, ivseg1->data, ivseg1->size, ivseg1->size, ivseg1->ref_count);
    IVM_LOCK_OBJ_UNLOCK();
    return ivseg1->data;
}

int ivshmem_dt(void* data) {
    IVM_LOCK_OBJ_LOCK();
    ivshmem_check();
    int ii;
    for (ii=0; ii<IVSHMEM_SEGMENT_LIST_LEN; ii++) {
        ivshmem_segment* ivseg1 = ivsegments + ii;
        if (ivseg1->unused())
            continue;
        if (ivseg1->data == data) {
            ivseg1->ref_count--;
            debugf_ivshmem("IVSHMEM dt id=%d data=%p size=%d=%p ref_count=%d\n", ivseg1->id, ivseg1->data, ivseg1->size, ivseg1->size, ivseg1->ref_count);
            if (ivseg1->ref_count == 0) {
                debugf_ivshmem("IVSHMEM dt id=%d removed\n", ivseg1->id);
                ivsegments[ii].remove();
            }
            IVM_LOCK_OBJ_UNLOCK();
            return 0;
        }
    }
    // segment not found
    IVM_LOCK_OBJ_UNLOCK();
    errno = EINVAL;
    return -1;
}

} // extern "C"
