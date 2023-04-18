import hashlib
from .utils import debug


def round_trip(conn, data):
    conn.write_packet(data)
    packet = conn.read_packet()
    return packet


def scramble_sha256_password(password: str, nonce: bytes):
    """ Nonce - 20 byte long random data
        XOR(SHA256(password), SHA256(SHA256(SHA256(password)), Nonce))"""
    if not password:
        return b""
    password = password.encode("utf8")

    hash1 = hashlib.sha256(password).digest()
    hash2 = hashlib.sha256(hash1).digest()
    hash3 = hashlib.sha256(hash2 + nonce).digest()

    res = bytearray(hash1)
    for i in range(len(hash3)):
        res[i] ^= hash3[i]

    return bytes(res)


def auth_sha256_password(conn, packet):
    # No password fast path
    if not conn.password:
        return round_trip(conn, b"")

    # magic numbers:
    # 2 - request public key
    # 3 - fast auth succeeded
    # 4 - need full auth
    packet.read(1)
    magic_number = packet.read_uint8()
    if magic_number == 2 and not conn.server_public_key:
        print("request public key")

    if magic_number == 3:
        debug("Successfully auth via fast auth")
        pkt = conn.read_packet()
        return pkt

    if magic_number != 4:
        raise Exception("Unknown caching_sha256_password auth...")

    if conn.secure:
        debug("Successfully auth via secure conn")
        return round_trip(conn, str(conn.password).encode("utf8") + b"\0")
