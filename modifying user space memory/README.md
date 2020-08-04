# Modifying User space memory

This program is only written to make sure that, you will never commit memroy error's while writing eBPF code.

* If you didn't have ```bcc``` , please install it, or else you can see ```README.md``` from main page of this repo for steps to setup requirements.

## Usage

* run ```python2 modify.py``` with ```sudo``` permissions.
* Now open another terminal and  try to view the content of ```foo1``` using ```cat foo1```.
* if you have seen ```this is foo1 content``` try running ```cat foo1``` again.

 Your'e going to see the output which looks like below

```
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo2 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo2
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo2
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo1 content
$ cat foo1
this is foo2 content
```


* you can see  only sometime's it is  working correctly, So the reson for this is ```bpf_probe_write_user()``` returns ```-EFAULT (-14)``` most of the time, indicating that it failed to copy ```foo2``` to ```fname```. I haven't found how to fix that so far.

* you can see the output of ```modify.py```, it print's each and every file opend by the linux-kernel.

* even ```two.py``` does the same thing with less code, But initially I am need of some debugging to know what exactly kernel is doing on ```open syscall``` so I wrote ```modify.py``` , So ```modify.py``` print's the fined grained information which is not done by ```two.py```.




