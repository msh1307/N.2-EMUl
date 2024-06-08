# EMUl
선린 에뮬레이터 개발 프로젝트
```
> make test
gcc  -c src/main.c -o src/main.o
gcc  -c src/util.c -o src/util.o
gcc  -c src/elf.c -o src/elf.o
gcc  -c src/emul.c -o src/emul.o
gcc  -c src/syscalls.c -o src/syscalls.o
gcc  -c src/user_defined_hooks.c -o src/user_defined_hooks.o
gcc -o app.out ./src/main.o ./src/util.o ./src/elf.o ./src/emul.o ./src/syscalls.o ./src/user_defined_hooks.o -lunicorn -lpthread -lm -lelf -lcapstone
gcc  -c tests/test.c -o tests/test.o
gcc  tests/test.o -o test.out
./app.out ./test.out
[+] Loader path: /lib64/ld-linux-x86-64.so.2
[+] Entrypoint: 0x7ffff7fe3290
[+] Mapping Memory [0x7ffff7fc3000 ~ 0x7ffff7fc5000 (0x2000)] FileOffset=0x0 FLAGS=0x4
[+] Mapping Memory [0x7ffff7fc5000 ~ 0x7ffff7fef000 (0x2a000)] FileOffset=0x2000 FLAGS=0x5
[+] Mapping Memory [0x7ffff7fef000 ~ 0x7ffff7ffa000 (0xb000)] FileOffset=0x2c000 FLAGS=0x4
[+] Mapping Memory [0x7ffff7ffb000 ~ 0x7ffff7fff000 (0x4000)] FileOffset=0x37620 FLAGS=0x6
[+] Writing Memory [0x7ffff7fc3000 ~ 0x7ffff7fc4b50 (0x1b50)]
[+] Writing Memory [0x7ffff7fc5000 ~ 0x7ffff7fee315 (0x29315)]
[+] Writing Memory [0x7ffff7fef000 ~ 0x7ffff7ff9f34 (0xaf34)]
[+] Writing Memory [0x7ffff7ffb620 ~ 0x7ffff7ffe110 (0x2af0)]
[+] Entrypoint: 0x555555555060
[+] Mapping Memory [0x555555554000 ~ 0x555555555000 (0x1000)] FileOffset=0x0 FLAGS=0x4
[+] Mapping Memory [0x555555555000 ~ 0x555555556000 (0x1000)] FileOffset=0x1000 FLAGS=0x5
[+] Mapping Memory [0x555555556000 ~ 0x555555557000 (0x1000)] FileOffset=0x2000 FLAGS=0x4
[+] Mapping Memory [0x555555557000 ~ 0x555555559000 (0x2000)] FileOffset=0x2db8 FLAGS=0x6
[+] Writing Memory [0x555555554000 ~ 0x555555554628 (0x628)]
[+] Writing Memory [0x555555555000 ~ 0x555555555175 (0x175)]
[+] Writing Memory [0x555555556000 ~ 0x5555555560f4 (0xf4)]
[+] Writing Memory [0x555555557db8 ~ 0x555555558010 (0x258)]
[+] Mapping Stack  [0x7ffffffde000 ~ 0x7ffffffee000 (0x10000)]
[+] rsp = 0x7ffffffede50

0x0000000000000001 0x00007ffffffedfb2 
0x0000000000000000 0x0000000000000000 
0x0000000000000033 0x00000000000006f0 
0x0000000000000010 0x00000000078bfbfd 
0x0000000000000006 0x0000000000001000 
0x0000000000000011 0x0000000000000064 
0x0000000000000003 0x0000555555554040 
0x0000000000000004 0x0000000000000038 
0x0000000000000005 0x000000000000000d 
0x0000000000000007 0x00007ffff7fc3000 
0x0000000000000008 0x0000000000000000 
0x0000000000000009 0x0000555555555060 
0x000000000000000b 0x0000000000000000 
0x000000000000000c 0x0000000000000000 
0x000000000000000d 0x0000000000000000 
0x000000000000000e 0x0000000000000000 
0x0000000000000017 0x0000000000000000 
0x0000000000000019 0x00007ffffffedfbd 
0x000000000000001f 0x00007ffffffedfcd 
0x000000000000000f 0x00007ffffffedff1 
0x0000000000000000 0x0000000000000000 
0x0000000000000000 0x0000000000000000 
0x747365742f2e0000 0x4141410074756f2e 
0x4141414141414141 0x6f722f4141414141 
0x736b726f572f746f 0x322e4e2f65636170 
0x2f2e2f6c554d452d 0x74756f2e74736574 
0x0034365f36387800 0x0000000000000000 

[+] Running /root/Workspace/N.2-EMUl/./test.out
[+] emul: brk(0x0)
[+] emul: arch_prctl(0x3001, 0x7ffffffedc90)
[+] emul: sys_uname(0x7ffffffed870)
[-] emul: sys_access("/etc/ld.so.preload", 0x4) == 0xffffffffffffffff
[+] emul: sys_openat(0xffffff9c, "/etc/ld.so.cache", 0x80000, 0x0)
[+] emul: sys_newfstatat(0x3, "", 0x7ffffffecde0, 0x1000)
[+] emul: sys_mmap(0x0, 0x1115f, 0x1, 0x2, 0x3, 0x0) == 0x7ffff7fb1000
[+] emul: sys_close(0x3)
[+] emul: sys_openat(0xffffff9c, "/lib/x86_64-linux-gnu/libc.so.6", 0x80000, 0x0)
[+] emul: sys_read(0x4, 0x7ffffffed018, 0x340) == 0x340
[+] emul: sys_pread64(0x4, 0x7ffffffecc20, 0x310, 0x40) == 0x310
[+] emul: sys_pread64(0x4, 0x7ffffffecbe0, 0x30, 0x350) == 0x30
[+] emul: sys_pread64(0x4, 0x7ffffffecb90, 0x44, 0x380) == 0x44
[+] emul: sys_newfstatat(0x4, "", 0x7ffffffeceb0, 0x1000)
[+] emul: sys_pread64(0x4, 0x7ffffffecaf0, 0x310, 0x40) == 0x310
[+] emul: sys_mmap(0x0, 0x228e50, 0x1, 0x802, 0x4, 0x0) == 0x7ffff7d88000
[+] emul: sys_mprotect(0x7ffff7db0000, 0x1ee000, 0x0)
[+] emul: sys_mmap(0x7ffff7db0000, 0x195000, 0x5, 0x812, 0x4, 0x28000) == 0x7ffff7db0000
[+] emul: sys_mmap(0x7ffff7f45000, 0x58000, 0x1, 0x812, 0x4, 0x1bd000) == 0x7ffff7f45000
[+] emul: sys_mmap(0x7ffff7f9e000, 0x6000, 0x3, 0x812, 0x4, 0x215000) == 0x7ffff7f9e000
[+] emul: sys_mmap(0x7ffff7fa4000, 0xce50, 0x3, 0x32, 0xffffffff, 0x0) == 0x7ffff7fa4000
[+] emul: sys_close(0x4)
[+] emul: sys_mmap(0x0, 0x2000, 0x3, 0x22, 0xffffffff, 0x0) == 0x7ffff7d86000
[+] emul: arch_prctl(0x1002, 0x7ffff7d870c0)
[+] emul: sys_set_tid_address(0x7ffff7d87390)
[+] emul: sys_set_robust_list(0x7ffff7d873a0, 0x18)
[+] emul: sys_rseq(0x7ffff7d87a60, 0x20, 0x0)
[+] Hooked at 0x7ffff7fe688e
[+] RIP = 0x7ffff7fe6894
[+] Hooked at 0x7ffff7fe688e
[+] RIP = 0x7ffff7fe6894
[+] emul: sys_mprotect(0x7ffff7f9e000, 0x4000, 0x1)
[+] emul: sys_mprotect(0x555555557000, 0x1000, 0x1)
[+] emul: sys_mprotect(0x7ffff7ffb000, 0x2000, 0x1)
[+] emul: sys_prlimit64(0x0, 0x3, 0x0, 0x7ffffffed9f0)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0xb, rdi=0x7ffff7fb1000, rsi=0x1115f, rdx=0x7ffff7e18c10)
[+] emul: sys_newfstatat(0x1, "", 0x7ffffffedbb0, 0x1000)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0x13e, rdi=0x7ffff7fa94d8, rsi=0x8, rdx=0x1)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0xe4, rdi=0x1, rsi=0x7ffffffedb40, rdx=0x1)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0xe4, rdi=0x1, rsi=0x7ffffffedb40, rdx=0x1)
[+] emul: brk(0x0)
[+] emul: brk(0x55555557a000)
[+] emul: write(fd=0x1, buf=0x5555555592a0, count=0xd)
Hello World!
[+] emul: exit()
0.073835sec
```
