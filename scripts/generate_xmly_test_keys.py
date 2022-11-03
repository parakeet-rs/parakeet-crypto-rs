#!/usr/bin/env python3

import random
import struct

# Fixed random state.
random.seed(0x12345678)

table = []
for i in range(1024):
    table.append(i)

for i in range(1024):
    swap_index = random.randint(0, 1023)
    table[i], table[swap_index] = table[swap_index], table[i]

data = bytearray()
for i in range(1024):
    data += struct.pack('<H', table[i])

with open('./test_xmly_scramble_table.bin', 'wb') as f:
    f.write(data)

test_x2m_key = random.randbytes(4)
test_x3m_key = random.randbytes(32)

with open('./test_x2m_key.bin', 'wb') as f:
    f.write(test_x2m_key)

with open('./test_x3m_key.bin', 'wb') as f:
    f.write(test_x3m_key)
