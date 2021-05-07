/*
    eBPF program to drop TCP packets for a given port
*/

#include <linux/bpf.h>      // contains all ebpf definitions
#include <linux/if_ether.h> // defines link layer header struct
#include <linux/ip.h>       // defines IPv4 header struct
#include <linux/tcp.h>      // defines TCP header struct

/*
#include <bpf/bpf_helpers.h>    // already provided by BCC
*/



/* 
    -Array of 1 element 
    -Stores ports to be blocked
    -Is pinned to the bpffs filesystem so that other ebpf programs can access it
*/
BPF_TABLE_PINNED("array", int, u64, ports_blocked, 1, "/sys/fs/bpf/portblock/ports_blocked");

/*
    -This our ebpf program which will be attached to the XDP hook
    -it parses the packet data into headers
*/
int drop_tcp_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 
    struct ethhdr *eth = data;
    
    int zero = 0;                                       // index
    u64* port_blocked = ports_blocked.lookup(&zero);    // corresponding value in array == port to block
    
    // checking for NULL ptr
    if (port_blocked == 0) {
        bpf_trace_printk("Aborted!\n");
        return XDP_ABORTED; // signals exception
    }

    // port to be blocked has value 0
    if ((*port_blocked) == 0) {
        bpf_trace_printk("Uninitialized..\n");
        return XDP_PASS; // uninitialized 
    }

    //checking link header size boundary
    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);

        //checking ip header size boundary
        if ((void *)ip + sizeof(*ip) <= data_end) {
            
            // if protocol field is TCP
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                
                //checking TCP header size boundary
                if ((void *)tcp + sizeof(*tcp) <= data_end) {
                    
                    //if destination port field of packet == port to be blocked, we drop it
                    if (htons(tcp->dest) == (*port_blocked)) {
                        bpf_trace_printk("TCP Packet goingt to port = %ld dropped!\n", (*port_blocked));
                        return XDP_DROP;
                    } 
                    else {
                        //bpf_trace_printk("tcp packet allowed at port = %d \n", htons(tcp->dest));
                    }
                }
            }
        }
    }
    //bpf_trace_printk("Packet allowed\n");   

    return XDP_PASS;
}