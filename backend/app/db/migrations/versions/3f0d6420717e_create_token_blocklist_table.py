"""create token_blocklist table

Revision ID: 3f0d6420717e
Revises: f6838a3b4e20
Create Date: 2026-07-02 00:33:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3f0d6420717e'
down_revision: Union[str, Sequence[str], None] = 'f6838a3b4e20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the token_blocklist table to support server-side JWT revocation on logout."""
    op.create_table(
        'token_blocklist',
        sa.Column('jti', sa.String(36), primary_key=True, nullable=False),
        sa.Column('blocked_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_token_blocklist_jti', 'token_blocklist', ['jti'], unique=False)


def downgrade() -> None:
    """Drop the token_blocklist table."""
    op.drop_index('ix_token_blocklist_jti', table_name='token_blocklist')
    op.drop_table('token_blocklist')
