from __future__ import print_function
from bcc import BPF

from bcc.utils import printb

import ctypes as ct


prog="""
#include <linux/sched.h>

#include <linux/string.h>





BPF_HASH(map_three,u32,u32);

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(perf_map);




int do_trace(struct pt_regs *ctx){


    


   

  

  
    char comm[TASK_COMM_LEN];

   


    bpf_get_current_comm(&(comm), sizeof(comm));



    char b[]=COMMAND_NAME;

    for(int i=0;i<TASK_COMM_LEN;++i){
        if(!(comm[i]==b[i]))return 0;   
    }


   

  

    


    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();


    bpf_get_current_comm(&data.comm, sizeof(data.comm));


    struct task_struct *task;
    struct task_struct *real_parent_task;
    u32 ppid;

    task = (struct task_struct *)bpf_get_current_task();

    ppid=task->real_parent->tgid;






    perf_map.perf_submit(ctx, &data, sizeof(data));


    return 0;






}


""";


prog=prog.replace("COMMAND_NAME",'"x-terminal-emul"')

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="do_trace")








class map_two_s(ct.Structure):
    _fields_ = [('name', ct.c_char*16)
                ]


print("%-18s %-16s %-6s %-20s " % ("TIME(s)", "COMM", "PID", "MESSAGE"))


start = 0
def print_event(cpu, data, size):
    global start
    event = b["perf_map"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    s=str(event.ts)
    print(s)
    
    print("%-18.9f %-16s %-6d %-20s " % (time_s, event.comm, event.pid,
         "Hello, perf_output!"))
        
    
        




b["perf_map"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

  