#!/usr/bin/env python3

import sys
import binascii
from io import StringIO

def main():
    if len(sys.argv) < 2:
        print(f"{sys.argv[0]} <file-payload.bin> <optional-ommit-last-n-bytes>")
        sys.exit(1)

    payload = None
    with open(sys.argv[1], "rb") as fh:
        payload = binascii.hexlify(fh.read(), " ")

    old_stdout = sys.stdout
    sys.stdout = new_stdout = StringIO()

    print(payload)    
    
    sys.stdout = old_stdout
    shellcode = new_stdout.getvalue().replace("'b", "").replace("'", "").replace("\n", "").split()
    
    o_last_bytes = abs(int(sys.argv[2])) * -1 if len(sys.argv) == 3 else len(shellcode) 
    print("\"", end="")
    for b in shellcode[:o_last_bytes]:
        print(f"\\x{b}", end="")
    print("\"")

if __name__ == '__main__':
    main()

