from app import app, db, User
import sys

if len(sys.argv) != 2:
    print("Usage: python get_admin.py <user_id>")
    sys.exit(1)

with app.app_context():
    user = User.query.get(sys.argv[1])
    user.is_admin = True
    db.session.commit()
    print("User is now an admin")