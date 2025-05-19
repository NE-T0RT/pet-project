"""Add category to Problem

Revision ID: e8f45d082d60
Revises: f27253a44870
Create Date: 2024-07-26 12:34:56.789012

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e8f45d082d60'
down_revision = 'f27253a44870'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category', sa.String(length=100), nullable=False, server_default='General'))

    # Remove the server default to ensure it's only used during the migration
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.alter_column('category', server_default=None)


def downgrade():
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.drop_column('category')
