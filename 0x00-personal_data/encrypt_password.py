#!/usr/bin/env python3
"""
Function called hash_password that returns hashed password.
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    yields a hashed password back
    Args:
        password (str): hashed password
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verify if password is legitimate
    Args:
        hashed_password (bytes): The hashed password
        password (str): a string password
    Return:
        bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
