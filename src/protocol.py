import struct
from .consts import CLIENT, SERVER_STATUS
from .charsets import Charsets
from .converts import decode_field_type

UNSIGNED_INT8 = 251
NULL_FIELD_TYPE = 0xFB
UNSIGNED_INT16 = 0xFC
UNSIGNED_INT24 = 0xFD
UNSIGNED_INT64 = 0xFE


class MysqlPacket:

    def __init__(self, buff: bytes):
        self._data = buff
        self._position = 0

    def get_all_data(self):
        return self._data

    def read(self, size: int):
        result = self._data[self._position:self._position + size]

        if len(result) != size:
            raise ValueError("Error read packet data!")

        self._position += size
        return result

    def read_all_data(self):
        result = self._data[self._position:]
        self._position = None
        return result

    def rewind(self, position=0):
        if position < 0 or position > len(self._data):
            raise Exception("Invalid position to rewind cursor to: %s." % position)
        self._position = position

    def read_string(self):
        end_pos = self._data.find(b"\x00", self._position)
        if end_pos < 0:
            return None
        result = self._data[self._position:end_pos]
        self._position += end_pos + 1
        return result

    def advance(self, size: int):
        self._position = self._position + size

    def is_error_packet(self):
        return self._data[0] == 0xFF

    def is_ok_packet(self):
        return len(self._data) >= 7 and self._data[0] == 0

    def is_eof_packet(self):
        return len(self._data) < 9 and self._data[0] == 0xFE

    def is_extra_auth_data(self):
        return self._data[0] == 1

    def is_switch_auth(self):
        return self._data[0] == 0xFE  # 254

    def is_result_set(self):
        field_count = self._data[0]
        return 1 <= field_count <= 250

    def is_local_infile(self):
        return self._data[0] == 0xFB

    def is_null_type(self):
        return self._data[self._position] == 0xFB

    def raise_error_packet(self):
        # header
        self.read(1)
        code, = struct.unpack("<H", self.read(2))
        # sql marker
        self.read(1)
        # sql_state https://en.wikipedia.org/wiki/SQLSTATE
        sql_state = self.read(5).decode("utf-8")
        # print(sql_state)
        message = self.read_all_data().decode("utf-8")
        raise ErrorPacket(code, message, sql_state)

    def read_uint8(self):
        return struct.unpack("<B", self.read(1))[0]

    def read_uint16(self):
        return struct.unpack("<H", self.read(2))[0]

    def read_uint24(self):
        low, high = struct.unpack("<BH", self.read(3))
        return low + (high << 8)

    def read_uint32(self):
        return struct.unpack("<I", self.read(4))[0]

    def read_uint64(self):
        return struct.unpack("<Q", self.read(8))[0]

    def read_length_encoded_integer(self):
        """ Read Length-Encoded Integer.
            Depending on first byte read whole number """
        uint = self.read_uint8()
        if uint < UNSIGNED_INT8:
            return uint
        if uint == UNSIGNED_INT16:
            return self.read_uint16()
        if uint == UNSIGNED_INT24:
            return self.read_uint24()
        if UNSIGNED_INT64 == UNSIGNED_INT64:
            return self.read_uint64()

    def read_length_encoded_string(self):
        """Read a 'Length Coded String' from the data buffer.
            A 'Length Coded String' consists first of a length coded
            (unsigned, positive) integer represented in 1-9 bytes followed by
            that many bytes of binary data.  (For example "cat" would be "3cat".)
        """
        if self.is_null_type():
            return None
        length = self.read_length_encoded_integer()
        if length is None:
            return None
        return self.read(length)

    def __repr__(self):
        return f"<MysqlPacket size={len(self._data)}>"


class OKMysqlPacket:
    """ Implementation of Mysql OK-Packet """
    def __init__(self, from_packet: MysqlPacket):
        if not from_packet.is_ok_packet():
            raise ValueError(f"Cannot create {str(self.__class__.__name__)} object from invalid packet type")
        self.packet = from_packet
        # header
        self.packet.advance(1)

        self.affected_rows = self.packet.read_length_encoded_integer()
        self.last_insert_id = self.packet.read_length_encoded_integer()
        self.server_status, self.warns_count = struct.unpack("<HH", self.packet.read(4))
        if self.server_status & SERVER_STATUS.SERVER_SESSION_STATE_CHANGED:
            session_state_info = self.packet.read_length_encoded_integer()
            print("session_state_info", session_state_info)
        self.message = self.packet.read_all_data()
        self.has_next = bool(self.server_status & SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS)

        # print(self.affected_rows, self.last_insert, self.has_next)

    def __getattr__(self, item):
        return getattr(self.packet, item)

    def __repr__(self):
        return f"<OKMysqlPacket size='{len(self.packet.get_all_data())}'>"


class EOFMysqlPacket:
    """ Implementation of Mysql EOF-Packet """

    def __init__(self, from_packet: MysqlPacket):
        if not from_packet.is_eof_packet():
            raise ValueError(f"Cannot create {str(self.__class__.__name__)} object from invalid packet type")

        self.packet = from_packet
        # header
        self.packet.advance(1)
        self.server_status, self.warns_count = struct.unpack("<HH", self.packet.read(4))

    def __getattr__(self, item):
        return getattr(self.packet, item)

    def __repr__(self):
        return f"<EOFMysqlPacket size='{len(self.packet.get_all_data())}'>"


class ErrorPacket(Exception):
    """ Implementation of Mysql ERR-Packet """

    def __init__(self, errno: int, message: str, sql_state: str):
        message = f"ERROR {errno} ({sql_state}): {message}"
        super().__init__(message)
        self.errno = errno
        self.sql_state = sql_state
        self.message = message

    def __repr__(self):
        return f"<ErrorPacket message='{self.message}'>"


class DescriptionField:
    def __init__(self, db_name,
                 table_name,
                 table_org_name,
                 col_name,
                 col_org_name,
                 charset,
                 max_col_len,
                 field_type,
                 flags,
                 decimal):
        """
        :param db_name: Database name
        :param table_name: Virtual table name
        :param table_org_name: Physical table name
        :param col_name: Virtual column name
        :param col_org_name: Physical column name
        :param charset: Charsets
        :param max_col_len: Maximum length of the field
        :param field_type: Type of the column
        :param flags: Flags as defined in https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__column__definition__flags.html
        :param decimal: Max shown decimal digits:
                     - 0x00 for integers and static strings
                     - 0x1f for dynamic strings, double, float
                     - 0x00 to 0x51 for decimals
        """
        self.db_name = db_name
        self.table_name = table_name
        self.org_table_name = table_org_name
        self.col_name = col_name
        self.col_org_name = col_org_name
        self.charset = Charsets.find_by_id(charset)
        self.max_col_len = max_col_len
        self.type = field_type
        self.flags = flags
        self.decimal = decimal

    def __repr__(self):
        return f"<DescriptionField table='{self.table_name}' " \
               f"name='{self.col_name}' " \
               f"max_length='{self.max_col_len}' " \
               f"type='{self.type}'>"


class MysqlResult:
    def __init__(self, conn):
        """
        :param conn: MySqlConnector
        """
        self.conn = conn
        self.affected_rows = 0
        self.warnings_count = 0
        self.fields_count = 0
        self.last_inserted_id = 0
        self.has_next = False
        self.message = None
        self.server_status = None
        self.unbuffered_active = False
        self.data = []

    def read(self):
        try:
            packet: MysqlPacket = self.conn.read_packet()
            if packet.is_ok_packet():
                self._read_ok_packet(packet)
            elif packet.is_local_infile():
                raise NotImplementedError("'LOCAL INFILE Data' doesn't implement")
            else:
                self._read_result(packet)
        finally:
            self.conn = None

    def _read_ok_packet(self, packet: MysqlPacket):
        ok = OKMysqlPacket(packet)
        self.affected_rows = ok.affected_rows
        self.last_inserted_id = ok.last_insert_id
        self.server_status = ok.server_status
        self.warnings_count = ok.warns_count
        self.has_next = ok.has_next
        self.message = ok.message

    def _read_result(self, first_packet: MysqlPacket):
        self.fields_count = first_packet.read_length_encoded_integer()
        self._read_fields()
        self._read_rows()

    def _read_fields(self):
        self.fields = []
        if self.conn.server_status & CLIENT.OPTIONAL_RESULTSET_METADATA:
            raise Exception("Flag specifying if metadata are skipped or not. See enum_resultset_metadata")
        for _ in range(self.fields_count):
            field = self._read_col_definition()
            self.fields.append(field)
        terminated_pck = self.conn.read_packet()
        if not terminated_pck.is_eof_packet():
            raise Exception("_read_fields: Terminated Error!")

    def _read_col_definition(self):
        packet: MysqlPacket = self.conn.read_packet()
        # Catalog currently always def
        packet.read_length_encoded_string()

        db_name = packet.read_length_encoded_string().decode(self.conn.encoding)
        table_name = packet.read_length_encoded_string().decode(self.conn.encoding)
        org_table_name = packet.read_length_encoded_string().decode(self.conn.encoding)
        col_name = packet.read_length_encoded_string().decode(self.conn.encoding)
        col_org_name = packet.read_length_encoded_string().decode(self.conn.encoding)
        # length of fixed length fields. Always have value 0x0c
        packet.read_length_encoded_integer()

        charset = struct.unpack("<H", packet.read(2))[0]
        max_col_len = struct.unpack("<I", packet.read(4))[0]
        field_type = struct.unpack("<B", packet.read(1))[0]
        flags = struct.unpack("<H", packet.read(2))[0]
        dec = struct.unpack("<B", packet.read(1))[0]

        return DescriptionField(db_name=db_name,
                                table_name=table_name,
                                table_org_name=org_table_name,
                                col_name=col_name,
                                col_org_name=col_org_name,
                                charset=charset,
                                max_col_len=max_col_len,
                                field_type=field_type,
                                flags=flags,
                                decimal=dec)

    def _read_rows(self):
        self.data = []
        while True:
            packet: MysqlPacket = self.conn.read_packet()
            if packet.is_eof_packet():
                break

            row = {}
            for i in range(self.fields_count):
                cell_data = packet.read_length_encoded_string()
                if isinstance(cell_data, bytes):
                    cell_data = cell_data.decode(self.conn.encoding)
                if cell_data is None:
                    row[self.fields[i].col_name] = None
                else:
                    row[self.fields[i].col_name] = decode_field_type(self.fields[i].type, cell_data)
            self.data.append(row)
            i += 1

