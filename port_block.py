#!/bin/env python
from bcc import BPF 
import ctypes as ct
import netifaces as neti


"""
    This simple program takes a TCP port as an input and blocks traffic going to that port.
    Dummy TCP traffic can be generated using `nc localhost <blocked_port>`.
    Example: nc localhost 5000

    Output will be emitted by the ebpf program everytime it drops a packet.
    The program is attached at the lowest possible level (XDP hook).

    Note: Run this program as a superuser.
"""

#   takes the port to blocked as well as the list of network interfaces
def block_tcp_port(port, devices):
    # contructor creates BPF object from the ebpf C source code
    b = BPF(src_file="drop_tcp_packets.c")

    # loads specific section from the C file to be attached 
    # second arguments tells the type of ebpf Program
    fn = b.load_func("drop_tcp_packet", BPF.XDP) 

    # initialize the ebpf map (array) associated with our program
    b['ports_blocked'].__setitem__(ct.c_int(0), ct.c_uint64(port))

    # attach our ebpf packet filter at each interface's XDP hook
    for device in devices:
        b.remove_xdp(device, 0)     # remove/unload the already present ebpf hooks
        b.attach_xdp(device, fn, 0) # attach our ebpf program to the XDP hook for given interface   


    try:
        b.trace_print()             # prints trace_pipe output emitted by the ebpf program attached by us
                                    # the attached programs will remain active even after exitting the program
                                    # the output can seen using `sudo cat /sys/kernel/tracing/trace_pipe`
        print("this exited")        
    except KeyboardInterrupt:       # use keyboard interrupt to exit
        print("exitting...") 

# stores list of network device interface names
net_devices = neti.interfaces()

# stores which TCP port to block
port_blocked = int(input("Enter the TCP Port to block:"))

block_tcp_port(port_blocked, net_devices)