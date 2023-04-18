from .consts import FIELD_TYPES


def through(x):
    return x


decoders = {
    FIELD_TYPES.DECIMAL: float,
    FIELD_TYPES.TINY: int,
    FIELD_TYPES.SHORT: int,
    FIELD_TYPES.LONG: int,
    FIELD_TYPES.FLOAT: float,
    FIELD_TYPES.DOUBLE: float,
    FIELD_TYPES.TIMESTAMP: through,
    FIELD_TYPES.LONGLONG: int,
    FIELD_TYPES.INT24: int,
    FIELD_TYPES.DATE: through,
    FIELD_TYPES.TIME: through,
    FIELD_TYPES.DATETIME: through,
    FIELD_TYPES.YEAR: int,
    FIELD_TYPES.NEWDATE: through,
    FIELD_TYPES.VARCHAR: str,
    FIELD_TYPES.BIT: int,
    FIELD_TYPES.JSON: str,
    FIELD_TYPES.BOOL: bool,
    FIELD_TYPES.TINY_BLOB: through,
    FIELD_TYPES.MEDIUM_BLOB: through,
    FIELD_TYPES.LONG_BLOB: through,
    FIELD_TYPES.BLOB: through,
    FIELD_TYPES.VAR_STRING: str,
    FIELD_TYPES.STRING: str
}


def decode_field_type(field_type: int, value):
    return decoders[field_type](value)
