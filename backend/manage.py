# Simple CLI to create users
import sys, os
from getpass import getpass
from app import SessionLocal, User, get_password_hash

def main():
    if len(sys.argv) < 3:
        print("Usage: python manage.py create-user <username> <password> [--role creator|consumer|admin]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd != "create-user":
        print("Unknown command:", cmd); sys.exit(1)
    username = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else getpass("Password: ")
    role = "consumer"
    if "--role" in sys.argv:
        i = sys.argv.index("--role")
        role = sys.argv[i+1]
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username==username).first():
            print("User exists")
            return
        u = User(username=username, password_hash=get_password_hash(password), role=role)
        db.add(u); db.commit()
        print("Created", username, "role", role)
    finally:
        db.close()

if __name__ == "__main__":
    main()
