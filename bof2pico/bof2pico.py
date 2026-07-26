#!/usr/bin/env python3

import binascii, sys, struct, subprocess

def parse_args(args):
    buffer = b""
    
    for arg in args:
        parts = arg.split(":")
        if len(parts) < 2:
            raise ValueError("Invalid format specifier, precede arguments with one of 'zZis' followed by a colon, i.e. 'z:C:\\Users\\wirt'")

        format = parts[0]
        payload = ":".join(parts[1:])

        if format == "z":
            buffer += struct.pack("<I", len(payload) + 1)
            buffer += payload.encode("utf-8")
            buffer += b"\x00"
            continue          
        if format == "Z":
            payload_encoded = payload.encode("utf-16_le")
            buffer += struct.pack("<I", len(payload_encoded) + 2)
            buffer += payload_encoded
            buffer += b"\x00\x00"
            continue
        if format == "i":
            buffer += struct.pack("<i", int(payload))
            continue
        if format == "s":
            buffer += struct.pack("<h", int(payload))
            continue

        raise ValueError("Invalid format specifier, precede arguments with one of 'zZis' followed by a colon, i.e. 'z:C:\\Users\\wirt'")

    size = struct.pack("<I", len(buffer))
    buffer = size + buffer
    return binascii.hexlify(buffer).decode("utf-8")

if len(sys.argv) < 3:
    print("USAGE: bof2pico /path/to/bof.0 /path/to/output.pico [optional arguments]")
    sys.exit()

bof_path = sys.argv[1]
pico_path = sys.argv[2]

cmd = ["cpl","link", "./bof2pico.spec", bof_path, pico_path, "$BOF_ARGS=00"]

if len(sys.argv) > 3:
    args = parse_args(sys.argv[3:])
    cmd[5] = f"$BOF_ARGS={args}"

print("[+] Executing: make all")
subprocess.call(["make", "all"])

print("[+] Executing: {}".format(" ".join(cmd)))
subprocess.call(cmd)

