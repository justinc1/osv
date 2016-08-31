/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include "drivers/virtio-ivshmem.hh"

#include <osv/mmu.hh>
#include <algorithm>
#include <iterator>

using namespace std;

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
