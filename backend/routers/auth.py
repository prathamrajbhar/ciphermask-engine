"""
Authentication Router
Handles user registration, login, and profile endpoints.

Security: Users always register as standard users.
Admin accounts are created only via the CLI tool (create_admin.py).
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import RegisterRequest, LoginRequest, TokenResponse, UserOut
from utils.security import hash_password, verify_password, create_access_token, get_current_user
from services.audit import log_action
import models

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new standard user account."""
    existing = db.query(models.User).filter(models.User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = models.User(
        name=req.name,
        email=req.email,
        password_hash=hash_password(req.password),
        role=models.UserRole.USER,  # Always standard user via API
    )
    db.add(user)
    db.flush()

    log_action(db, user.id, "register", "user", user.id, ip_address=_client_ip(request))
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        role=user.role.value,
        name=user.name,
    )


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login with email and password."""
    user = db.query(models.User).filter(models.User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    log_action(db, user.id, "login", "user", user.id, ip_address=_client_ip(request))
    db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        role=user.role.value,
        name=user.name,
    )


@router.get("/me", response_model=UserOut)
def get_me(current_user: models.User = Depends(get_current_user)):
    """Get current user profile."""
    return current_user
