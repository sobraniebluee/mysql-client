import os
import socket
import struct

from .auth import scramble_sha256_password, auth_sha256_password
from .charsets import (Charsets)
from .consts import CLIENT, CONFIG, COMMANDS, SERVER_STATUS
from .protocol import MysqlPacket, OKMysqlPacket, MysqlResult, ErrorPacket
from .utils import debug, pack_int3, length_encoded_int

import src.errors


class MySqlConnector:
    _sock = None
    _rfile = None

    def __init__(self,
                 database=None,
                 username=None,
                 password=None,
                 charset=None,
                 unix_sock=None,
                 host=None,
                 port=None,
                 autocommit=False
                 ):
        self.username = username
        self.password = password
        self.charset = Charsets.find_by_name(charset) or Charsets.find_by_id(CONFIG.DEFAULT_CHARSET)
        self.encoding = self.charset.encoding
        self.server_public_key = None
        self.unix_sock = unix_sock
        self.host = host or "127.0.0.1"
        self.port = port or 3306
        self.database = database
        self.secure = False
        self._closed = False
        self.autocommit_mode = autocommit
        self._next_seq_id = 0
        self._result = None
        client_flag = CLIENT.CAPABILITIES

        if self.database:
            client_flag |= CLIENT.CONNECT_WITH_DB

        self.client_flag = client_flag

    def connect(self):
        try:
            if self.unix_sock:
                if not os.path.exists(self.unix_sock):
                    raise AttributeError("Unix socket doesn't exists!")
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect(self.unix_sock)
                self.secure = True
                debug("Connecting using unix_sock")
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.host, self.port))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                debug("Connecting using TCP")
            self._sock = sock
            self._rfile = sock.makefile('rb')
            self._initial_handshake()
            self._auth_requested()

            if self.autocommit_mode is not None:
                self.autocommit(self.autocommit_mode)

        except Exception as e:
            print(e)
            self._rfile = None
            if self._sock is not None:
                self._force_close()
            raise e

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        del exc_info
        self.close()

    @property
    def closed(self):
        return self._closed is None

    def close(self):
        self._closed = True
        self._force_close()

    def query(self, sql):
        self._execute(COMMANDS.COM_QUERY, sql)
        return self._read_query_result()

    def autocommit(self, value: bool):
        self.autocommit_mode = bool(value)
        if value != self.is_autocommit():
            self._set_autocommit_mode()

    def is_autocommit(self):
        return bool(self.server_status & SERVER_STATUS.AUTOCOMMIT)

    def begin(self):
        self._execute(COMMANDS.COM_QUERY, "BEGIN")
        self._read_ok_packet()

    def commit(self):
        self._execute(COMMANDS.COM_QUERY, "COMMIT")
        self._read_ok_packet()

    def rollback(self):
        self._execute(COMMANDS.COM_QUERY, "ROLLBACK")
        self._read_ok_packet()

    def fetchone(self):
        if self._result:
            return self._result[0]
        return None

    def fetchmany(self, count: int):
        if self._result:
            pass

    def fetchall(self):
        pass

    def _set_autocommit_mode(self):
        print("set autocommit", self.autocommit_mode)

    def _execute(self, command, sql):
        if isinstance(sql, str):
            sql = sql.encode(self.charset.encoding)

        packet = struct.pack("<B", command)
        packet += sql
        self._next_seq_id = 0
        self.write_packet(packet)

    def _read_query_result(self):
        self._result = None
        result = MysqlResult(self)
        result.read()
        self._result = result
        if result.server_status is not None:
            self.server_status = result.server_status
        return self._result.affected_rows

    def _initial_handshake(self):
        # Initial Handshake https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
        packet = self.read_packet()
        # Read version protocol
        self.protocol_version, = struct.unpack('<B', packet.read(1))
        # Read server version
        self.server_version = packet.read_string()
        # Thread id
        self._thread_id = struct.unpack("<I", packet.read(4))
        # _auth_plugin_data (salt)
        self.salt = packet.read(8)
        # capabilities_flags low 2 bytes
        self.server_capabilities = struct.unpack("<H", packet.read(2))[0]
        # charset id,
        # server status flags - https://dev.mysql.com/doc/dev/mysql-server/latest/mysql__com_8h.html#a1d854e841086925be1883e4d7b4e8cad
        # capabilities_flags high 2 bytes
        # salt_len
        charset, status_flags, cap_high, salt_len = struct.unpack("<BHHB", packet.read(6))
        self.server_status = status_flags
        self.server_capabilities |= cap_high << 16
        self.server_charset = Charsets.find_by_id(charset)
        # reserved
        packet.read(10)

        salt_len = max(13, salt_len - 8)
        self.salt += packet.read(salt_len)

        if self.server_capabilities & CLIENT.PLUGIN_AUTH:
            self._auth_plugin_name = packet.read_string().decode("utf-8")

        # print(self._thread_id, self.salt, self.server_charset, self._auth_plugin_name)

    def _auth_requested(self):
        # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
        buff_init = struct.pack("<IIB23s",
                                self.client_flag,
                                CONFIG.MAX_PACKET_LEN,
                                self.charset.id_charset,
                                b"")

        buff_init += f"{self.username}".encode(self.charset.encoding) + b"\0"
        auth_response = b""
        plugin_name = b""

        if self._auth_plugin_name == b"":
            pass
        elif self._auth_plugin_name == CONFIG.CACHING_256_PASSWORD:
            plugin_name = b"caching_sha2_password"
            auth_response = scramble_sha256_password(self.password, self.salt)
            if not self.password:
                debug("Password empty")

        if self.server_capabilities & CLIENT.PLUGIN_AUTH_LENENC_DATA:
            buff_init += length_encoded_int(len(auth_response)) + auth_response
            # buff_init += struct.pack("B", len(auth_response)) + auth_response
        else:
            buff_init += auth_response + b"\0"

        if self.database and self.server_capabilities & CLIENT.CONNECT_WITH_DB:
            if isinstance(self.database, str):
                self.database = str(self.database).encode(self.charset.encoding)
            buff_init += self.database + b"\0"

        if self.server_capabilities & CLIENT.PLUGIN_AUTH:
            buff_init += (plugin_name or b"") + b"\0"

        self.write_packet(buff_init)
        auth_packet = self.read_packet()

        if auth_packet.is_switch_auth():
            debug("Switch auth")
            return
        elif auth_packet.is_extra_auth_data():
            debug("Extra auth data")
            if self._auth_plugin_name == CONFIG.CACHING_256_PASSWORD:
                auth_packet = auth_sha256_password(conn=self, packet=auth_packet)

        debug("Successfully auth")

    def write_packet(self, data: bytes):
        buff = pack_int3(len(data)) + bytes([self._next_seq_id]) + data
        self._write_bytes(buff)
        self._next_seq_id = (self._next_seq_id + 1) % 256

    def read_packet(self, packet_class=MysqlPacket):
        # Read headers
        # - payload_length: int<int3store>, sequence_id: int<1>, payload: string
        buff = bytes()
        while True:
            packet_header = self._read_bytes(4)
            byte_r, byte_l, packet_number = struct.unpack("<HBB", packet_header)
            bytes_to_read = byte_r + (byte_l << 16)
            if packet_number != self._next_seq_id:
                self._force_close()
                raise ValueError("Packet number didn't match! Server: %s, Client: %s" % (packet_number, self._next_seq_id))

            self._next_seq_id = (self._next_seq_id + 1) % 256
            recv_data = self._read_bytes(bytes_to_read)
            buff += recv_data
            if bytes_to_read == 0xFFFFFF:
                continue
            if bytes_to_read < CONFIG.MAX_PACKET_LEN:
                break

        packet = packet_class(bytes(buff))
        if packet.is_error_packet():
            packet.raise_error_packet()
        return packet

    def _read_ok_packet(self, packet: MysqlPacket = None):
        if not packet:
            packet = self.read_packet()
        if not packet.is_ok_packet():
            raise Exception("Mysql Packet is not ok")
        ok = OKMysqlPacket(packet)
        self.server_status = ok.server_status
        return ok

    def _read_bytes(self, num_bytes):
        self._sock.settimeout(1)
        while True:
            try:
                data = self._rfile.read(num_bytes)
                break
            except (IOError, OSError) as e:
                self._force_close()
                raise Exception(e)

        if len(data) < num_bytes:
            self._force_close()
            raise ValueError("Requested length of bytes is larger than available")
        return data

    def _write_bytes(self, data: bytes):
        self._sock.settimeout(1)
        try:
            self._sock.sendall(data)
        except IOError as e:
            debug(f"_write_bytes: {e}")
            self._force_close()

    def _force_close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                debug("Error close socket")

        self._sock = None
        self._rfile = None

