from bcc import BPF

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
int trace_entry(struct pt_regs *ctx)
{
    char buf[10];
    char foo2[] = "foo2";
    char *fname = (char *) PT_REGS_PARM2(ctx);
    

    bpf_probe_read_user_str(buf, sizeof(buf), fname);
   
    if (buf[0] != 'f' || buf[1] != 'o' || buf[2] != 'o' || buf[3] != '1') {
        return 0;
    }

    bpf_probe_write_user((char *) PT_REGS_PARM2(ctx), foo2, sizeof(foo2));


    bpf_trace_printk("%s :-> Done",buf);
    return 0;
};
"""

# load BPF program
b = BPF(text=prog)
#b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.attach_kprobe(event="do_sys_open" ,fn_name="trace_entry")


print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))


while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if(msg):
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
