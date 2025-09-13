import sys
import binascii

# Open the file in binary mode and read its contents
name = sys.argv[1]

with open(name, 'rb') as f:
    data = f.read()

# Convert the bytes object to a hex string
hex_data = binascii.hexlify(data)

# Insert commas between every two hex digits
hex_data_with_commas = ',0x'.join(hex_data[i:i+2].decode('ascii') for i in range(0, len(hex_data), 2))

# Print or write the resulting string
print(hex_data_with_commas)