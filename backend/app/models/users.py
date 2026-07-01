import uuid
from sqlalchemy import String, DateTime, Integer, Column
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.session import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default = uuid.uuid4)

    github_id = Column(Integer, nullable=False, unique=True,index = True)
    github_login = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    github_token = Column(String(500), nullable=False)
    github_installation_id = Column(Integer, nullable=True)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    last_login_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self):
        return f"<User {self.github_login}>"