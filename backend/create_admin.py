"""
CipherMask – Create Admin User
Run: python create_admin.py
"""
import sys
import os

# Ensure the backend directory is on the path
sys.path.insert(0, os.path.dirname(__file__))

from database import SessionLocal, init_db
from utils.security import hash_password
from models import User, UserRole


def main():
    init_db()
    db = SessionLocal()

    print("=== CipherMask – Create Admin ===\n")

    name = input("Admin name: ").strip()
    email = input("Admin email: ").strip()
    password = input("Admin password: ").strip()

    if not all([name, email, password]):
        print("Error: All fields are required.")
        sys.exit(1)

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        print(f"Error: User with email '{email}' already exists.")
        db.close()
        sys.exit(1)

    user = User(
        name=name,
        email=email,
        password_hash=hash_password(password),
        role=UserRole.ADMIN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()

    print(f"\n✅ Admin user created successfully!")
    print(f"   ID:    {user.id}")
    print(f"   Name:  {user.name}")
    print(f"   Email: {user.email}")
    print(f"   Role:  {user.role.value}")


if __name__ == "__main__":
    main()
