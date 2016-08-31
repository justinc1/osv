/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#ifndef VIRTIO_IVSHMEM_DRIVER_H
#define VIRTIO_IVSHMEM_DRIVER_H

//#include <osv/condvar.h>
#include <osv/device.h>
//#include <osv/mutex.h>

#include "drivers/virtio.hh"
#include "drivers/device.hh"

#include <vector>

namespace virtio {

class ivshmem : public virtio_driver {
public:
    enum {
        VIRTIO_IVSHMEM_DEVICE_ID = 0x1110,
    };

    explicit ivshmem(pci::device& dev);
    virtual ~ivshmem();

    virtual std::string get_name() const { return "virtio-ivshmem"; }

    static hw_driver* probe(hw_device* dev);

    volatile void* get_data();
    size_t get_size();

private:

    void handle_irq();
    bool ack_irq();

    pci_interrupt _irq;
    volatile void* _data;
    size_t _size;
};

}

#endif
