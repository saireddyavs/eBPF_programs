# eBPF_programs

## Installation
* upgrade the linux kernel if your'e having older versions ,  you can this [reference link](https://www.freecodecamp.org/news/building-and-installing-the-latest-linux-kernel-from-source-6d8df5345980/).
* Now setup or compile ```bcc``` on your'e system , you can use this [reference link](https://github.com/iovisor/bcc/blob/master/INSTALL.md) for installing ```bcc``` on OS of your'e choice.
*  For more fine grained visualization and suppourt optionally you can setup ```bpftool``` 

```
 $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
 $ cd linux
 $ cd tools/bpf/bpftool
 $ make

 ```

## Details

The programs which are going to be added in future are at the end of this list.
1. [Terminal](https://github.com/saireddyavs/eBPF_programs/tree/master/terminal), This is my first program and it tracks and debugs when a new is opened.
2. [Modifying user space memory](https://github.com/saireddyavs/eBPF_programs/tree/master/modifying%20user%20space%20memory), Just to make sure that you will commit a mistake, using eBPF in wrong way will cause memory problems.
3. [bloc Write Syscall](https://github.com/saireddyavs/eBPF_programs/tree/master/block%20write%20syscall), This program block's ```write syscall``` whenever the ```write syscall``` is made.

