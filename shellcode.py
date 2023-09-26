#!/usr/bin/env python3

import sys
import binascii

def main():
    if len(sys.argv) != 2:
        print(f"{sys.argv[0]} <file-payload.bin>")
        sys.exit(1)
    bin_file = sys.argv[1]
    print("\"", end=""); 
    with open(bin_file, "rb") as fh:
        payload = binascii.hexlify(fh.read(), " ")
        print(payload)
    print("\"")
if __name__ == '__main__':
    main()

