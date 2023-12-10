# NTUST Intro Computer Science

This is my final project
About how to bypass DEP on windows 11 latest version

For compile
```
gcc -o vuln.exe vuln.c -lws2_32 -fno-stack-protector -Wl,--image-base,0x1120000
```
