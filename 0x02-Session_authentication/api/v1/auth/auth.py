#!/usr/bin/env python3
"""
The class Auth
"""
import os
from flask import request
from typing import (
    List,
    TypeVar
)


class Auth:
    """
    oversees the authentication of API
    """
    def require_auth self path: str excluded_paths: List[str] bool:
        """
        Determines whether a given path requires authentication or not
        Args:
            - path(str): Url route needs to be verified
            - excluded_paths(List of str): path not need authenticate
        Return:
            - Verified path is not in excluded_paths if not, False
        """
        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        elif path in excluded_paths:
            return False
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i[-1] == "*":
                    if path.startswith(i[:-1]):
                        return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        returns the request object authorization header
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        gives back User instance based on data from request object
        """
        return None

    def session_cookie(self, request=None):
        """
        gives back a cookie based on a request
        Args:
            request : the request object
        Return:
            _my_session_id cookie value from request object
        """
        if request is None:
            return None
        session_name = os.getenv('SESSION_NAME')
        return request.cookies.get(session_name)
