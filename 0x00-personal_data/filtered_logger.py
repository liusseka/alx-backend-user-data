#!/usr/bin/env python3
"""
This script defines a function `filter_datum` to obfuscate
sensitive information in log messages.
It uses a custom logging formatter to redact fields like
name, email, phone, SSN, and password.

The script interacts with a MySQL database to retrieve
user data and logs it with redacted sensitive fields.
"""

from typing import List
import re
import logging
import os
import mysql.connector

# List of fields that are considered personally identifiable information (PII)
PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Obfuscates sensitive information in a log message by replacing
    specified fields with a redaction value.

    Args:
        fields (List[str]): List of field names (e.g., 'name',
        'email', etc.) to redact.
        redaction (str): The string to replace sensitive field
        values with (e.g., "***").
        message (str): The log message containing the data to
        be redacted.
        separator (str): The separator character between
        key-value pairs in the log message.

    Returns:
        str: The log message with sensitive fields replaced
        by the redaction value.
    """
    for field in fields:
        # Use regex to match field=value pairs and replace
        # them with the redacted value
        message = re.sub(field + r'=[^' + re.escape(separator) + r']+',
                         field + '=' + redaction, message)
    return message


class RedactingFormatter(logging.Formatter):
    """
    Custom logging formatter that redacts sensitive data from log messages.
    """

    REDACTION = "***"  # Default redaction string
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the formatter with the fields to be redacted.

        Args:
            fields (List[str]): List of field names to redact
            in the log messages.
        """
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats a LogRecord and applies redaction to the message.

        Args:
            record (logging.LogRecord): The log record containing
            the message to redact.

        Returns:
            str: The formatted log message with sensitive data redacted.
        """
        message = super().format(record)
        # Apply the filtering function to redact sensitive fields
        redacted_message = filter_datum(self.fields,
                                        self.REDACTION,
                                        message,
                                        self.SEPARATOR)
        return redacted_message


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger instance to log user data with redaction.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Create a stream handler for logging to console
    handler = logging.StreamHandler()

    # Create and set the redacting formatter
    formatter = RedactingFormatter(PII_FIELDS)
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes a connection to the MySQL database containing user data.

    Returns:
        mysql.connector.connection.MySQLConnection:
        MySQL database connection object.
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    # Connect to the database using the environment variables or defaults
    conn = mysql.connector.connect(user=user,
                                   password=passwd,
                                   host=host,
                                   database=db_name)
    return conn


def main():
    """
    Main entry point of the script.
    Retrieves user data from the database and logs it with
    redacted sensitive information.
    """
    # Establish database connection
    db = get_db()

    # Create a logger instance
    logger = get_logger()

    # Retrieve user data from the database
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = cursor.column_names

    # Log each row from the database, redacting sensitive fields
    for row in cursor:
        message = "".join("{}={}; ".format(k, v) for k, v in zip(fields, row))
        logger.info(message.strip())  # Log the message with redacted data

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
