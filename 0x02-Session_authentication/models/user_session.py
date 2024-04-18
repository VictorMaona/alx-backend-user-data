#!/usr/bin/env python3
"""session for user.
"""
from models.base import Base


class UserSession(Base):
    """Session user class.
    """

    def __init__(self, *args: list, **kwargs: dict):
        """User Initializes session.
        """
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
