from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Cookie, Response
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from app.config import settings
from app.db.session import get_db
from app.models.users import User
from app.models.user_preferences import UserPreferences
from app.models.token_blocklist import TokenBlocklist
from app.services.encryption import encrypt_token
from app.services.auth import (
    exchange_github_code_for_token,
    fetch_github_user_info,
    create_jwt_token,
    verify_jwt_token,
    get_current_user,
    purge_expired_blocklist
)

router = APIRouter()

@router.get("/login")
def login():
    """
    Redirects the user to the GitHub OAuth authorize page with a secure state parameter.
    """
    import secrets
    state = secrets.token_urlsafe(32)
    scope = "read:user"
    github_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_CLIENT_ID}"
        f"&scope={scope}"
        f"&state={state}"
    )
    response = RedirectResponse(url=github_url)
    
    secure_cookie = settings.ENVIRONMENT != "development"
    # Store state in a short-lived secure cookie
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=300,  # 5 minutes expiration
        path="/auth"
    )
    return response

@router.get("/callback")
def callback(
    code: str,
    state: Optional[str] = None,
    installation_id: Optional[int] = None,
    oauth_state: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    """
    Handles the GitHub OAuth redirect callback. Verification of state prevents CSRF.
    Exchanges authorization code, creates/updates the user profile, and redirects
    to the frontend dashboard.
    """
    # 0. Verify OAuth state to prevent CSRF
    if not state or not oauth_state or state != oauth_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state mismatch or expired. Potential CSRF attack."
        )
    
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code missing"
        )
    
    # 1. Exchange code for GitHub access token
    access_token = exchange_github_code_for_token(code)
    
    # 2. Fetch user information from GitHub
    github_user = fetch_github_user_info(access_token)
    github_id = github_user.get("id")
    github_login = github_user.get("login")
    display_name = github_user.get("name") or github_login
    avatar_url = github_user.get("avatar_url")
    
    if not github_id or not github_login:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve complete user details from GitHub"
        )
        
    # 3. Encrypt the access token
    encrypted_token = encrypt_token(access_token)
    
    # 4. Check if user already exists
    user = db.query(User).filter(User.github_id == github_id).first()
    
    if user:
        # Update existing user info and token
        user.github_login = github_login
        user.display_name = display_name
        user.avatar_url = avatar_url
        user.github_token = encrypted_token
        user.last_login_at = func.now()
        if installation_id is not None:
            user.github_installation_id = installation_id
    else:
        # Create new user
        user = User(
            github_id=github_id,
            github_login=github_login,
            display_name=display_name,
            avatar_url=avatar_url,
            github_token=encrypted_token,
            github_installation_id=installation_id
        )
        db.add(user)
        db.flush()  # Flushes to DB to populate user.id UUID
        
        # Initialize UserPreferences
        preferences = UserPreferences(user_id=user.id)
        db.add(preferences)
        
    db.commit()
    db.refresh(user)
    
    # 5. Generate application JWT Access and Refresh tokens
    access_token_jwt = create_jwt_token(str(user.id), token_type="access")
    refresh_token_jwt = create_jwt_token(str(user.id), token_type="refresh")
    
    # 6. Redirect to Frontend Dashboard without token in query params
    redirect_url = f"{settings.FRONTEND_URL}/dashboard"
    response = RedirectResponse(url=redirect_url)
    
    secure_cookie = settings.ENVIRONMENT != "development"
    
    # Delete the single-use oauth_state cookie
    response.delete_cookie(
        key="oauth_state",
        path="/auth",
        secure=secure_cookie,
        httponly=True,
        samesite="lax"
    )
    
    # Set the access token as a secure, HTTP-only, SameSite=Lax cookie
    response.set_cookie(
        key="access_token",
        value=access_token_jwt,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    
    # Set the refresh token as a secure, HTTP-only, SameSite=Strict cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token_jwt,
        httponly=True,
        secure=secure_cookie,
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/auth"  # Restrict cookie transmission to auth endpoints
    )
    
    return response

@router.post("/refresh")
def refresh(response: Response, refresh_token: Optional[str] = Cookie(None)):
    """
    Exchanges a valid refresh token cookie for a new short-lived access token,
    setting the new access token in an HTTP-only cookie.
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )
    
    payload = verify_jwt_token(refresh_token, expected_type="refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    user_id = payload.get("sub")
    new_access_token = create_jwt_token(user_id, token_type="access")
    
    # Set the new access token as a secure, HTTP-only, SameSite=Lax cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=settings.ENVIRONMENT != "development",
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    
    return {"access_token": new_access_token}

@router.post("/logout")
def logout(
    response: Response,
    access_token: Optional[str] = Cookie(None),
    refresh_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    """
    Logs out the user by:
    1. Adding the JTI of both tokens to the blocklist so they are immediately invalid.
    2. Deleting the HTTP-only cookies from the browser.
    """
    secure_cookie = settings.ENVIRONMENT != "development"

    # Block the access token so it cannot be reused even if someone kept a copy
    if access_token:
        payload = verify_jwt_token(access_token, expected_type="access")
        if payload and payload.get("jti"):
            db.add(TokenBlocklist(jti=payload["jti"]))

    # Block the refresh token so it cannot be used to mint new access tokens
    if refresh_token:
        payload = verify_jwt_token(refresh_token, expected_type="refresh")
        if payload and payload.get("jti"):
            db.add(TokenBlocklist(jti=payload["jti"]))

    # Purge blocklist rows that are older than the max token lifetime —
    # they could never be replayed as valid tokens anyway.
    purge_expired_blocklist(db)

    db.commit()

    response.delete_cookie(
        key="refresh_token",
        path="/auth",
        secure=secure_cookie,
        httponly=True,
        samesite="strict"
    )
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=secure_cookie,
        httponly=True,
        samesite="lax"
    )
    return {"message": "Successfully logged out"}

@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    """
    Returns details of the currently authenticated user.
    """
    return {
        "id": str(current_user.id),
        "github_id": current_user.github_id,
        "github_login": current_user.github_login,
        "display_name": current_user.display_name,
        "avatar_url": current_user.avatar_url,
        "created_at": current_user.created_at,
        "last_login_at": current_user.last_login_at
    }

