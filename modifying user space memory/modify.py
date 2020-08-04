from bcc import BPF
from bcc.utils import printb
from datetime import datetime, timedelta








bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};
struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};
BPF_PERF_OUTPUT(events);

BPF_HASH(infotmp, u64, struct val_t);
int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u64 tsp = bpf_ktime_get_ns();
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}


int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename, int flags)
{
struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
  
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    char foo2[] = "foo2";
    char buf[10];
    bpf_probe_read_user_str(buf, sizeof(buf),(char *)  filename);
    if (buf[0] != 'f' || buf[1] != 'o' || buf[2] != 'o' || buf[3] != '1') {
        return 0;
    }
    bpf_probe_write_user((char *) filename, foo2, sizeof(foo2));
    return 0;
};


int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
  
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    char foo2[] = "foo2";
    char buf[10];
    bpf_probe_read_user_str(buf, sizeof(buf),(char *)  filename);
    if (buf[0] != 'f' || buf[1] != 'o' || buf[2] != 'o' || buf[3] != '1') {
        return 0;
    }
    bpf_probe_write_user((char *) filename, foo2, sizeof(foo2));
    return 0;
};


#include <uapi/linux/openat2.h>
int syscall__trace_entry_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    int flags = how->flags;
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
  
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    char foo2[] = "foo2";
    char buf[10];
    bpf_probe_read_user_str(buf, sizeof(buf),(char *)  filename);
    if (buf[0] != 'f' || buf[1] != 'o' || buf[2] != 'o' || buf[3] != '1') {
        return 0;
    }
    bpf_probe_write_user((char *) filename, foo2, sizeof(foo2));
    return 0;
};

"""


b=BPF(text="")
# open and openat are always in place since 2.6.q
fnname_open = b.get_syscall_prefix().decode() + 'open'
fnname_openat = b.get_syscall_prefix().decode() + 'openat'
fnname_openat2 = b.get_syscall_prefix().decode() + 'openat2'

b = BPF(text=bpf_text)



b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
b.attach_kretprobe(event=fnname_open, fn_name="trace_return")
b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
b.attach_kretprobe(event=fnname_openat, fn_name="trace_return")

b.attach_kprobe(event=fnname_openat2, fn_name="syscall__trace_entry_openat2")
b.attach_kretprobe(event=fnname_openat2, fn_name="trace_return")

initial_ts = 0

print("%-6s %-16s %4s %3s " %
      ( "PID", "COMM", "FD", "ERR"), end="")

print("PATH")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global initial_ts

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if not initial_ts:
        initial_ts = event.ts

    


    printb(b"%-6d %-16s %4d %3d " %
           (event.id &  event.id >> 32,
            event.comm, fd_s, err), nl="")

  

    printb(b'%s' % event.fname)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()