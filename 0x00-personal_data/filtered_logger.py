#!/usr/bin/env python3
'''Filtering logs's module
'''
from typing import List, Tuple
import re
import logging
from datetime import datetime
import os
import mysql.connector


patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def asc_time() -> str:
    """Returns the current time.
    """
    cur_time = datetime.now()
    cur_time_ms = cur_time.microsecond // 1000
    return str('{},{}'.format(cur_time.strftime("%F %X"), cur_time_ms))


def get_values(record: logging.LogRecord, msg: str) -> Tuple[str]:
    """Retrieves values to be printed for a log record.
    """
    asctime = asc_time()
    return (record.name, record.levelname, asctime, msg.replace(';', '; '))


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Filters a log line.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Creates a new logger for user data.
    """
    logger = logging.Logger("user_data", logging.INFO)
    stream_handler = logging.StreamHandler()
    stream_handler.formatter = RedactingFormatter(PII_FIELDS)
    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    '''Connect with mysql database
    '''
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    '''Logs all the user information about user record
    in a table by filltering out the sensetive information
    '''
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formats a Log Record.
        """
        tmp = record.getMessage()
        msg = filter_datum(self.fields, self.REDACTION, tmp, self.SEPARATOR)
        values = get_values(record, msg)
        return self.FORMAT % dict(zip(self.FORMAT_FIELDS, values))


if __name__ == '__main__':
    main()
