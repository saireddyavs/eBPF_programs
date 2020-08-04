
# Terminal

These programs are written to explore different helper functions and maps available in eBPF, and also looking at actual ```bpf instructions```.

# Details

* These programs are written to trace when a new terminal is opened.

* ```terminal_1.py``` print's ```command-name, process-id, count of number of times process-id invoked by a syscall, count of number of times command is executed by  a syscall```.
* In ```terminal_2.py``` extra ```parent-process-id``` is also printed.
* Upto now I have compared the command name to have terminal in user-space python code, but in ```terminal_3.py``` I have comapared the command name in kernel-space.
* I am passing ```x-terminal-emul``` as an argument to the C-code, you can change this and use whatever command name you want to trace.
* Why ```x-terminal-emul```?, The answer is , I have first used ```bpf_trace_printk()``` and noticed that ```x-terminal-emul``` and ```gnome-terminal``` are the command names invoking inside when the new terminal is opened.


# For actuall BPF instuction

* Firstly make sure that you ```bpftool``` installed, if not you can see the main page of this repo for steps to install.

*  run any of the above code of your'e choice, ```python3 terminal_1.py``` with ```sudo``` permissions.

* Now list the active BPF programs using ```bpftool prog show```.

* your'e program will be listed at the end, make a note on ```id``` of your'e program from this output.

* ```sudo apt-get install graphviz``` for saving the visualizing instructions in the form of image.

* ```sudo bpftool prog dump xlated id 18 visual &> output.out && sudo dot -Tpng output.out -o terminal_1.png``` replace 18 with your'e ```id``` from ```bpftool prog show command```.


# points

* you can see the number of instructions in each program ```termina_1.py < terminal_2.py < termnial_3.py" .

* As I have used for-loop having return statemt on condition fail in ```terminal_3.py```, you can see the DAG have more lines connected to ```EXIT```.

