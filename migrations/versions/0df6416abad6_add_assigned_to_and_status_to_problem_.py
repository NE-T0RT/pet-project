from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# Revision identifiers, used by Alembic.
revision = '0df6416abad6'
down_revision = 'e8f45d082d60'
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)

    # Check if the columns exist
    columns = [col['name'] for col in inspector.get_columns('problem')]

    with op.batch_alter_table('problem', schema=None) as batch_op:
        if 'assigned_to' not in columns:
            batch_op.add_column(sa.Column('assigned_to', sa.Integer(), nullable=True))
        if 'status' not in columns:
            batch_op.add_column(sa.Column('status', sa.String(length=50), nullable=False, server_default='New'))

    # Add foreign key constraint if the assigned_to column was added
    if 'assigned_to' not in columns:
        with op.batch_alter_table('problem', schema=None) as batch_op:
            batch_op.create_foreign_key('fk_assigned_to_user', 'user', ['assigned_to'], ['id'])

def downgrade():
    # Remove foreign key constraints first
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.drop_constraint('fk_assigned_to_user', type_='foreignkey')
    
    # Drop columns
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.drop_column('status')
        batch_op.drop_column('assigned_to')
