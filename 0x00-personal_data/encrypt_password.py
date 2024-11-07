#!/usr/bin/env python3
"""
This script provides functions for securely hashing passwords
and verifying password validity using the bcrypt hashing algorithm.
"""

import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Hashes a given password using bcrypt.

    Args:
        password (str): The plain-text password to be hashed.

    Returns:
        bytes: The hashed password, suitable for storage in a secure manner.

    The function encodes the plain-text password and applies
    bcrypt's hashing function, which includes a salt to make
    the hash unique and secure.
    """
    # Encode the password to bytes and hash it
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verifies whether the provided password matches the stored hashed password.

    Args:
        hashed_password (bytes): The hashed password stored in
        the database or system.
        password (str): The plain-text password to be verified.

    Returns:
        bool: True if the password is valid (matches the hashed password),
        False otherwise.

    This function compares the plain-text password with the
    stored hash using bcrypt's
    `checkpw` function, ensuring that the password verification
    process is secure.
    """
    # Check if the password matches the hashed version
    return bcrypt.checkpw(password.encode(), hashed_password)
