#include <linux/bpf.h>


BPF_TABLE_PINNED("array", int, u64, ports_block, 1, "/sys/fs/bpf/portblock/ports_blocked");