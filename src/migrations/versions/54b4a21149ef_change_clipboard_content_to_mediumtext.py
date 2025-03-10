"""Change Clipboard content to MediumText

Revision ID: 54b4a21149ef
Revises: 46b348990980
Create Date: 2025-02-19 21:15:47.932172

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '54b4a21149ef'
down_revision = '46b348990980'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.alter_column('content',
               existing_type=mysql.LONGTEXT(),
               type_=sa.Text(length=16777215),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.alter_column('content',
               existing_type=sa.Text(length=16777215),
               type_=mysql.LONGTEXT(),
               existing_nullable=True)

    # ### end Alembic commands ###
