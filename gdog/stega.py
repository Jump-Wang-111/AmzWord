import sys
import time
from png import from_array, Reader
import base64
import os
import struct
import re
import argparse


def read_stdin():
    if sys.version_info >= (3, 0):
        source = sys.stdin.buffer
    else:
        set_binary_mode(sys.stdin)
        source = sys.stdin
    return source.read()


def bit_stream(data):
    # length
    for byte in struct.pack('!H', len(data)):
        for shift in range(0, 8, 2):
            yield (ord(byte) >> shift) & 3
    # data
    for byte in data:
        for shift in range(0, 8, 2):
            yield (ord(byte) >> shift) & 3


def pixel_stream(pixels):
    for y in range(len(pixels)):
        row = pixels[y]
        for x in range(len(row)):
            yield x, y, row[x]


def read_payload(path):
    if path == '-':
        return read_stdin()
    elif os.path.isfile(path):
        return open(path, 'rb').read()
    elif re.match('^[0-9a-f]+$', path, re.IGNORECASE):
        if sys.version_info >= (3, 0):
            return bytes.fromhex(path)
        else:
            return path.decode('hex')
    elif re.match('^[a-z0-9+/=]+$', path, re.IGNORECASE):
        return base64.b64decode(path)

def png_encode(paylaod_path, in_png_path, out_png_path):
    width, height, pixels, meta = Reader(bytes=read_payload(in_png_path)).asRGB8()

    # Each byte (8 bits) is encoded into 4 other bytes, 2 bits at the end of each byte.
    # Payload needs at least 4x bytes of it's size.
    # Image has 3 bytes per pixel (RGB)
    payload = read_payload(paylaod_path)
    if len(payload) * 4 >= width * height * 3:
        sys.stderr.write('Image is too small')
        exit(-1)

    pixels = list(pixels)
    for b, (x, y, c) in zip(bit_stream(payload), pixel_stream(pixels)):
        # print(b, (x, y, c))
        c &= 0b11111100         # zero-out last two bits
        c |= b                  # encode new to bits
        pixels[y][x] = c

    from_array(pixels, 'RGB').save(out_png_path)
    print(out_png_path, 'saved')

def png_decode(png_path):
    width, height, pixels, meta = Reader(bytes=read_payload(png_path)).asRGB8()
    pixels = list(pixels)
    payload_len = 0
    
    # get len of payload
    for i in range(4):
        tmp = pixels[0][i]
        tmp &= 0b00000011
        payload_len = payload_len | (tmp << (i*2))
    payload_len = payload_len << 8          # high 8 bits
    byte_low = 0
    for i in range(4):
        tmp = pixels[0][i+4]
        tmp &= 0b00000011
        byte_low = byte_low | (tmp << (i*2))
    payload_len |= byte_low                 # low 8 bits
    print("payload len: ", payload_len)

    # get content of payload
    payload_list = []
    skip_len = 0
    byte_count = 0
    byte_value = 0
    for x, y, c in pixel_stream(pixels):
        skip_len += 1
        if skip_len <= 8:
            continue
        tmp = c
        tmp &= 0b00000011
        byte_value |= (tmp << (byte_count*2))
        byte_count += 1
        if byte_count == 4:
            byte_count = 0
            payload_list.append(chr(byte_value))
            byte_value = 0
        if(skip_len > 8 + payload_len * 4):
            break
    print(''.join(payload_list))

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', type=str, help='path of input file')
    parser.add_argument('-o', '--output', type=str, help='path of output file')
    parser.add_argument('-p', '--payload', type=str, help='payload to hide')
    
    args = parser.parse_args()

    # decode
    if not args.payload:
        png_decode(args.input)
        exit(0)
    # encode
    png_encode(args.payload, args.input, args.output)
    
    