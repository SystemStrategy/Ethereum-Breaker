/*
  Copyright 2019 Ben Rogowitz
  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
  FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

# pip install ecdsa
# pip install pysha3

from ecdsa import SigningKey, SECP256k1
import sha3
import sys
sys.tracebacklimit = 0
priv = '0'
count = 0

Hex_array = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']

for q in range(64):
    for w in range(16):
        for x in range(64):
            for y in range(16):
                key = ['4','c','1','0','b','8','6','e','5','c','6','1','7','d','e','6','2','7','8','f','8','1','5','3','a','6','7','0','f','8','6','5','e','b','d','1','a','e','9','b','7','6','3','7','7','8','0','8','1','d','0','1','4','2','4','f','b','1','e','8','c','e','0','a','c']
                def checksum_encode(addr_str): # Takes a hex (string) address as input
                    keccak = sha3.keccak_256()
                    out = ''
                    addr = addr_str.lower().replace('0x', '')
                    keccak.update(addr.encode('ascii'))
                    hash_addr = keccak.hexdigest()
                    for i, c in enumerate(addr):
                        if int(hash_addr[i], 16) >= 8:
                            out += c.upper()
                        else:
                            out += c
                    return '0x' + out

                keccak = sha3.keccak_256()

                key[q] = Hex_array[w]
                key[x] = Hex_array[y]

                priv = "".join(key)
                Value = bytes.fromhex(priv)
                #print (Value)

                count = count + 1
                try:
                    pub = SigningKey.from_string(Value,curve=SECP256k1)
                    pub = pub.get_verifying_key().to_string()
                    keccak.update(pub)
                    address = keccak.hexdigest()[24:]
                    #print (priv)
                    #print(x,"  ",y)
                    #print("Address:    ", checksum_encode(address))
                except Exception:
                    pass


                if('0xcd56477ecbabe0764ada3a95283b87241ce9cc08' == checksum_encode(address)):
                    print("Failed Attempts: ",count)
                    print("Private key:", priv)
                    print("Public key: ", pub.hex())
                    print("Address:    ", checksum_encode(address))
                    sys.exit("Congrats !!!")

