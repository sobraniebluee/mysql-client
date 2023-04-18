from .consts import CONFIG
import struct


def debug(self, *args, sep=' ', end='\n', file=None):
    if CONFIG.DEBUG:
        print(self, *args, sep=sep, end=end, file=file)


def pack_int3(n):
    return struct.pack("<I", n)[:3]


def pack_int1(n: int):
    return struct.pack("<B", n)[:1]


def length_encoded_int(i):
    if i < 0:
        raise ValueError(
            "Encoding %d is less than 0 - no representation in LengthEncodedInteger" % i
        )
    elif i < 0xFB:
        return bytes([i])
    elif i < (1 << 16):
        return b"\xfc" + struct.pack("<H", i)
    elif i < (1 << 24):
        return b"\xfd" + struct.pack("<I", i)[:3]
    elif i < (1 << 64):
        return b"\xfe" + struct.pack("<Q", i)
    else:
        raise ValueError(
            "Encoding %x is larger than %x - no representation in LengthEncodedInteger"
            % (i, (1 << 64))
        )


def int3store_decode(int3_bytes: bytes):
    if len(int3_bytes) < 3:
        raise Exception("Error")

    return int3_bytes[0] + (int3_bytes[1] << 8) + (int3_bytes[2] << 16)


def int3store_encode(num):
    buff = bytearray(3)
    buff[0] = num % 256
    buff[1] = (num >> 8) % 256
    buff[2] = (num >> 16) % 256
    return buff
