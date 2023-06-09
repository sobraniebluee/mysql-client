LONG_PASSWORD = 1
FOUND_ROWS = 2
LONG_FLAG = 4
CONNECT_WITH_DB = 8
NO_SCHEMA = 16
COMPRESS = 32
ODBC = 64
LOCAL_FILES = 128
IGNORE_SPACE = 256
PROTOCOL_41 = 512
INTERACTIVE = 1024
SSL = 2048
IGNORE_SIGPIPE = 4096
TRANSACTIONS = 8192
RESERVED = 16384
RESERVED2 = 32768
MULTI_STATEMENTS = (1 << 16)
MULTI_RESULTS = (1 << 17)
PS_MULTI_RESULTS = (1 << 18)
PLUGIN_AUTH = (1 << 19)
CONNECT_ATTRS = (1 << 20)
PLUGIN_AUTH_LENENC_DATA = (1 << 21)
CAN_HANDLE_EXPIRED_PASSWORDS = (1 << 22)
SESSION_TRACK = (1 << 23)
DEPRECATE_EOF = (1 << 24)
OPTIONAL_RESULTSET_METADATA = (1 << 25)
ZSTD_COMPRESSION_ALGORITHM = (1 << 26)
QUERY_ATTRIBUTES = (1 << 27)
MULTI_FACTOR_AUTHENTICATION = (1 << 28)
CAPABILITY_EXTENSION = (1 << 29)
SSL_VERIFY_SERVER_CERT = (1 << 30)
REMEMBER_OPTIONS = (1 << 31)
SECURE_CONNECTION = 1 << 15

CAPABILITIES = (
    LONG_PASSWORD
    | LONG_FLAG
    | PROTOCOL_41
    | TRANSACTIONS
    | MULTI_RESULTS
    | PLUGIN_AUTH
    | PLUGIN_AUTH_LENENC_DATA
)