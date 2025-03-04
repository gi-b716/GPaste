from app import app, db, User
import logging, time

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)
logFormatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logFile = logging.FileHandler("log/utils.log", encoding="utf-8", mode="a")
logFile.setLevel(logging.DEBUG)
logFile.setFormatter(logFormatter)
logger.addHandler(logFile)

def get_admin(args):
    user_id = args.user_id
    with app.app_context():
        user = User.query.get(user_id)
        user.is_admin = True
        db.session.commit()
        print("User {} is now an admin".format(user.username))
        logger.info("User {} is now an admin".format(user.username))

def init_db(args):
    with app.app_context():
        db.create_all()
        print("Database initialized")
        logger.info("Database initialized")

def allow_all_users(args):
    with app.app_context():
        users = User.query.all()
        for user in users:
            user.allow_create = True
            user.allow_login = True
        db.session.commit()
        print("All users are now allowed to create and login")
        logger.info("All users are now allowed to create and login")

import argparse

argparser = argparse.ArgumentParser()
subparsers = argparser.add_subparsers()

get_admin_parser = subparsers.add_parser("get_admin")
get_admin_parser.add_argument("user_id", type=int)
get_admin_parser.set_defaults(func=get_admin)

init_parser = subparsers.add_parser("init_db")
init_parser.set_defaults(func=init_db)

allow_all_users_parser = subparsers.add_parser("allow_all_users")
allow_all_users_parser.set_defaults(func=allow_all_users)

args = argparser.parse_args()
args.func(args)
