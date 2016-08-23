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


namespace virtio {
ivshmem::ivshmem(pci::device& pci_dev)
    : virtio_driver(pci_dev)
    , _irq(pci_dev, [&] { return ack_irq(); }, [&] { handle_irq(); })
{
    add_dev_status(VIRTIO_CONFIG_S_DRIVER_OK);


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

}
