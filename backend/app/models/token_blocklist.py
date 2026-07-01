from sqlalchemy import String, DateTime, Column
from sqlalchemy.sql import func

from app.db.session import Base


class TokenBlocklist(Base):
    """
    Stores the JTI (JWT ID) of invalidated tokens.
    When a user logs out, their access and refresh token JTIs are added here.
    get_current_user checks this table to reject tokens even before they expire.
    """
    __tablename__ = "token_blocklist"

    jti = Column(String(36), primary_key=True, nullable=False, index=True)
    blocked_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self):
        return f"<TokenBlocklist jti={self.jti}>"
