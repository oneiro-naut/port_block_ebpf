#!/bin/env python
from bcc import BPF
import ctypes as ct

new_port = int(input("Enter new port:"))
b = BPF(src_file="change_port.c")
try:
    print(b['ports_blocked'][0])
    b['ports_blocked'].__setitem__(ct.c_int(0), ct.c_uint64(new_port))
except:
    print("Program not attached yet")