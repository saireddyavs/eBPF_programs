
# block write syscall

 This program uses seccomb BPF filter to block the write syscall.

 ## Usage
Compile it 
 ```
gcc write_block.c -o write_block
```

Make sure your kernel has the right configs

```
cat /proc/config.gz| zcat  | grep -i CONFIG_SECCOMP
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
```


## Output examples

The program will only print the first "hey there!" then will exit

```bash
./write_block
Hello World!
```

* now we for seeing the output use ```strace```

use ```strace -f ./write_block "ls -la"``` 

you will see

```
write(1, "My name is sai Reddy\n", 21)  = -1 EPERM (Operation not permitted)
write(1, "Hello World\n", 12)           = -1 EPERM (Operation not permitted)

```
and also

```
[pid  3530] close(1)                    = 0
[pid  3530] write(2, "ls: ", 4)         = -1 EPERM (Operation not permitted)
[pid  3530] write(2, "write error", 11) = -1 EPERM (Operation not permitted)
[pid  3530] write(2, "\n", 1)           = -1 EPERM (Operation not permitted)
[pid  3530] exit_group(2)               = ?
```

referene:
1. [Lorenzo Fontana gist](https://gist.github.com/fntlnz/08ae20befb91befd9a53cd91cdc6d507).




