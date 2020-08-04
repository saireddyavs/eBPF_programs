from __future__ import print_function
from bcc import BPF

from bcc.utils import printb

import ctypes as ct


prog="""
#include <linux/sched.h>

#include <linux/string.h>


struct key_t {
    char name[TASK_COMM_LEN];
    
};

BPF_HASH(map_one,u32);

BPF_HASH(map_two, struct key_t);


struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(perf_map);



int do_trace(struct pt_regs *ctx){


    u32 pid = bpf_get_current_pid_tgid()>>32;
    


    map_one.increment(pid);

    char comm[TASK_COMM_LEN];


    bpf_get_current_comm(&(comm), sizeof(comm));    




    char b[]=COMMAND_NAME;

    for(int i=0;i<TASK_COMM_LEN;++i){
        if(!(comm[i]==b[i]))return 0;   
    }

  


    struct key_t key = {};

    bpf_get_current_comm(&(key.name), sizeof(key.name));


    



   

    map_two.increment(key);

    


    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));


    
   

    perf_map.perf_submit(ctx, &data, sizeof(data));


    return 0;






}




""";


prog=prog.replace("COMMAND_NAME",'"x-terminal-emul"')

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="do_trace")






map_one=b['map_one']
map_two=b['map_two']
print(map_one)

class map_two_s(ct.Structure):
    _fields_ = [('name', ct.c_char*16)
                ]


print("%-18s %-16s %-6s %-20s %-5s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE","PNT","CNT"))


start = 0
def print_event(cpu, data, size):
    global start
    event = b["perf_map"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    s=str(event.comm)
    if(s.find("terminal")!=-1):
        print("%-18.9f %-16s %-6d %-20s %-5d %d" % (time_s, event.comm, event.pid,
         "Hello, perf_output!",map_one.__getitem__(ct.c_uint32(event.pid)).value,map_two.__getitem__(map_two_s(event.comm)).value))
        
    
        




b["perf_map"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

  