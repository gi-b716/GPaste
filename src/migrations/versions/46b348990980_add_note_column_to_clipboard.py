"""Add note column to Clipboard

Revision ID: 46b348990980
Revises: 
Create Date: 2025-02-16 00:45:41.639474

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '46b348990980'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.add_column(sa.Column('note', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.drop_column('note')

    # ### end Alembic commands ###
