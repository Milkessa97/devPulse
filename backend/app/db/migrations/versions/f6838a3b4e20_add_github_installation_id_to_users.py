"""add github installation id to users

Revision ID: f6838a3b4e20
Revises: 4c3e6b4094a0
Create Date: 2026-07-01 17:50:27.678548

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6838a3b4e20'
down_revision: Union[str, Sequence[str], None] = '4c3e6b4094a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('github_installation_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'github_installation_id')
