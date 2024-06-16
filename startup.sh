#!/bin/bash

NIC1="00:13.0"
NIC2="00:14.0"
NIC3="00:15.0"

PAGE="2M"
SIZE="2G"

echo "load the network driver"
modprobe uio
modprobe uio_pci_generic

echo "bind first nic"
dpdk-devbind.py -b uio_pci_generic $NIC1
echo "bind second nic"
dpdk-devbind.py -b uio_pci_generic $NIC2
echo "bind second nic"
dpdk-devbind.py -b uio_pci_generic $NIC3
echo "setup huge pages"
dpdk-hugepages.py -p $PAGE --setup $SIZE

echo "setup done..."
