def to_ascii(hex_string):
    hex_string = hex_string.replace(' ', '')
    ascii_string = bytes.fromhex(hex_string).decode('ascii')
    return ascii_string

hex = "67 65 6D 61 73 74 69 6B 7B 31 5F 34 6D 5F 73 74 30 6D 70 65 64 5F 5F 5F 5F 68 6D 6D 6D 7D"

flag = to_ascii(hex)
print(flag)
