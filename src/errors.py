class Error(Exception):
    """Exception that is the base class of all other error exceptions.
    You can use this to catch all errors with one single except statement.
    Warnings are not considered errors and thus should not use this class as base."""


class Warning(Exception):
    """Exception raised for important warnings like data truncations while inserting, etc."""



