import uuid
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from logging.handlers import TimedRotatingFileHandler
from fastapi import FastAPI, HTTPException, Depends, Security, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, text

from database import init_database, get_db_session, Department, User, Prompt, Tag, UserStarredPrompt, prompt_user_shares, prompt_tags, LogEntry
from migrate_from_excel import migration
# Configure logging with monthly rotation
# log_dir = os.path.join(os.path.dirname(__file__), 'log')
# os.makedirs(log_dir, exist_ok=True)

# log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m')}.log")

# Create a custom handler that rotates monthly
# handler = TimedRotatingFileHandler(
#     filename=log_file,
#     when='midnight',  # Rotate at midnight
#     interval=1,       # Every 1 day
#     backupCount=0     # Keep all files
# )

# Custom namer to create monthly files
# def monthly_namer(default_name):
#     base = os.path.dirname(default_name)
#     # Get the date from the rotation
#     rotation_date = datetime.now()
#     return os.path.join(base, f"{rotation_date.strftime('%Y-%m')}.log")

# Check if we need to rotate to a new month
# def should_rollover(record):
#     current_month = datetime.now().strftime('%Y-%m')
#     file_month = os.path.basename(handler.baseFilename).replace('.log', '')
#     return current_month != file_month

# Custom rotating handler that checks monthly
# class MonthlyRotatingHandler(TimedRotatingFileHandler):
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.namer = monthly_namer
    
#     def shouldRollover(self, record):
#         current_month = datetime.now().strftime('%Y-%m')
#         current_file = os.path.basename(self.baseFilename).replace('.log', '')
#         return current_month != current_file
    
#     def doRollover(self):
#         # Update filename to current month
#         new_month = datetime.now().strftime('%Y-%m')
#         new_file = os.path.join(os.path.dirname(self.baseFilename), f"{new_month}.log")
#         self.baseFilename = new_file
        # No need to close/reopen as TimedRotatingFileHandler handles it

# Create the monthly rotating handler
# monthly_handler = MonthlyRotatingHandler(
#     filename=log_file,
#     when='midnight',
#     interval=1,
#     backupCount=0
# )

# monthly_handler.setFormatter(logging.Formatter(
#     '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# ))

# Configure the root logger
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)
# logger.addHandler(monthly_handler)

# Also add console handler for development
# console_handler = logging.StreamHandler()
# console_handler.setFormatter(logging.Formatter(
#     '%(asctime)s - %(levelname)s - %(message)s'
# ))
# logger.addHandler(console_handler)

app = FastAPI()

# Allow CORS for local development (from chrome-extension://...)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on startup
init_database()
migration()
# --- Pydantic Models (Data Validation) ---
class TeamResponse(BaseModel):
    id: str
    name: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    department_id: Optional[int] = None
    department_name: Optional[str] = None

class DepartmentResponse(BaseModel):
    id: int
    name: str

class PromptCreate(BaseModel):
    title: str
    body: str
    tags: List[str] = []

class PromptResponse(BaseModel):
    id: str
    title: str
    body: str
    tags: List[str] = []
    starred: bool = False
    views: int = 0
    visibility: str = "personal"  # "personal" or "public"
    owner_id: int
    owner_name: Optional[str] = None
    team_id: str = ""
    position: int = 0
    created_at: str
    updated_at: str
    # NEW: Sharing status fields
    is_shared: bool = False
    shared_count: int = 0
    shared_at: Optional[str] = None  # When this prompt was shared with the current user

class PromptUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    tags: Optional[List[str]] = None
    starred: Optional[bool] = None

class ReorderPayload(BaseModel):
    ordered_ids: List[str]

class SharePayload(BaseModel):
    user_ids: List[int] = []


class AuthLoginRequest(BaseModel):
    email: str
    password: str

class SetPasswordRequest(BaseModel):
    email: str
    password: str


# --- Security & Auth ---
API_KEY_HEADER = APIKeyHeader(name="Authorization")

# Mock auth for backwards compatibility
MOCK_TEAMS = [
    {"id": "team-aurum", "name": "Aurum Research", "access_token": "secret-token-aurum"}
]

# Legacy auth function (for backward compatibility with existing token flow)
async def get_current_user(token: str = Security(API_KEY_HEADER), db: Session = Depends(get_db_session)):
    """Get current user from token - simplified for demo"""
    bearer_token = token.replace("Bearer ", "")
    
    # For demo purposes, use a simple token mapping
    if bearer_token == "secret-token-aurum":
        # Return the first user from the database
        user = db.query(User).first()
        if not user:
            raise HTTPException(status_code=403, detail="No users found in database")
        return user
    
    raise HTTPException(status_code=403, detail="Invalid access token")

# New simplified auth function for prototype
async def get_current_user_from_header(x_user_id: str = Header(None), db: Session = Depends(get_db_session)):
    """Get current user from X-User-ID header - for prototype"""
    if not x_user_id:
        # logging.error("[AUTH ERROR] Missing X-User-ID header")
        raise HTTPException(status_code=403, detail="User ID header missing")
    
    try:
        user_id = int(x_user_id)
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            # logging.error(f"[AUTH ERROR] User not found for ID: {user_id}")
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except ValueError:
        # logging.error(f"[AUTH ERROR] Invalid user ID format: {x_user_id}")
        raise HTTPException(status_code=400, detail="Invalid user ID format")

# --- Helper Functions ---
def get_prompt_if_accessible(prompt_id: str, current_user: User, db: Session) -> Prompt:
    """Get prompt if user can access it (owns it OR it's shared with them)"""
    # First check if user owns the prompt
    prompt = db.query(Prompt).filter(
        and_(Prompt.id == prompt_id, Prompt.owner_id == current_user.id)
    ).first()
    
    if prompt:
        return prompt
    
    # Check if prompt is shared with user directly
    prompt = db.query(Prompt).filter(
        and_(
            Prompt.id == prompt_id,
            Prompt.shared_with_users.any(User.id == current_user.id)
        )
    ).first()
    
    return prompt
def get_or_create_tag(db: Session, tag_name: str) -> Tag:
    """Get existing tag or create new one"""
    tag_name = tag_name.strip().lower()
    if not tag_name:
        return None
    
    tag = db.query(Tag).filter(Tag.name == tag_name).first()
    if not tag:
        tag = Tag(name=tag_name)
        db.add(tag)
        db.flush()
    return tag

def update_prompt_tags(db: Session, prompt: Prompt, tag_names: List[str]):
    """Update prompt's tags"""
    # Clear existing tags
    prompt.tags.clear()
    
    # Add new tags
    if tag_names:
        for tag_name in tag_names:
            tag = get_or_create_tag(db, tag_name)
            if tag:
                prompt.tags.append(tag)

def prompt_to_response(prompt: Prompt, current_user_id: int, db: Session, include_tags: bool = True) -> PromptResponse:
    """Convert SQLAlchemy Prompt to Pydantic response model with per-user starring and sharing info"""
    # Check if current user has starred this prompt
    starred = db.query(UserStarredPrompt).filter(
        and_(
            UserStarredPrompt.user_id == current_user_id,
            UserStarredPrompt.prompt_id == prompt.id
        )
    ).first() is not None
    
    # Get sharing information  
    user_shares_count = db.execute(text(
        'SELECT COUNT(*) FROM prompt_user_shares WHERE prompt_id = :pid'
    ), {'pid': prompt.id}).scalar()
    
    is_shared = user_shares_count > 0
    
    # Get the shared_at timestamp for the current user
    shared_at = None
    current_user = db.query(User).filter(User.id == current_user_id).first()
    
    if current_user and prompt.owner_id != current_user_id:
        # Check direct user sharing
        user_share = db.execute(text(
            'SELECT shared_at FROM prompt_user_shares WHERE prompt_id = :pid AND user_id = :uid'
        ), {'pid': prompt.id, 'uid': current_user_id}).fetchone()
        
        if user_share:
            shared_at = user_share.shared_at
    
    return PromptResponse(
        id=prompt.id,
        title=prompt.title,
        body=prompt.body,
        tags=[tag.name for tag in prompt.tags] if include_tags and prompt.tags else [],
        starred=starred,  # Now per-user!
        views=0,  # Will be handled in future updates
        visibility="shared" if is_shared else "personal",  # Updated based on sharing logic
        owner_id=prompt.owner_id,
        owner_name=prompt.owner.name if prompt.owner else None,
        team_id="team-aurum",  # Mock team ID for backwards compatibility
        position=prompt.position,
        created_at=prompt.created_at,
        updated_at=prompt.updated_at,
        # NEW: Sharing status
        is_shared=is_shared,
        shared_count=user_shares_count,
        shared_at=shared_at
    )

# --- Logging Functions ---
# def log_action(db: Session, user_id: int, action: str, resource_id: str = None, message: str = ""):
#     """Simple logging function for MVP"""
#     try:
#         log_entry = LogEntry(
#             timestamp=datetime.now(timezone.utc).isoformat(),
#             level="INFO",
#             user_id=user_id,
#             action=action,
#             resource_id=resource_id,
#             message=message
#         )
#         db.add(log_entry)
#         # Don't commit here - let the main operation commit
#     except Exception as e:
#         # Don't let logging failures break the main operation
#         logging.error(f"Logging failed: {e}")

# --- Authentication Helper Functions ---
def hash_password(password: str) -> str:
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- API Endpoints ---


@app.get("/users", response_model=List[UserResponse])
async def get_users(current_user: User = Depends(get_current_user_from_header), db: Session = Depends(get_db_session)):
    """Get all users"""
    users = db.query(User).all()
    return [
        UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            department_id=user.department_id,
            department_name=user.department.name if user.department else None
        )
        for user in users
    ]

@app.get("/departments", response_model=List[DepartmentResponse])
async def get_departments(current_user: User = Depends(get_current_user_from_header), db: Session = Depends(get_db_session)):
    """Get all departments"""
    departments = db.query(Department).all()
    return [
        DepartmentResponse(id=dept.id, name=dept.name)
        for dept in departments
    ]

@app.get("/prompts", response_model=List[PromptResponse])
async def get_prompts(
    scope: str = "personal",
    q: Optional[str] = None,
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Get prompts based on scope"""
    search_info = f" | Search: '{q}'" if q else ""
    # logging.info(f"[GET PROMPTS] User: {current_user.email} | Scope: {scope}{search_info}")
    
    if scope == "personal":
        # Get user's own prompts
        query = db.query(Prompt).filter(Prompt.owner_id == current_user.id)
    elif scope == "public":
        # Get prompts shared with current user directly
        query = db.query(Prompt).filter(
            Prompt.shared_with_users.any(User.id == current_user.id)
        )
    else:
        query = db.query(Prompt).filter(Prompt.owner_id == current_user.id)
    
    # Apply search filter
    if q:
        q_lower = q.lower()
        query = query.filter(
            or_(
                Prompt.title.ilike(f"%{q}%"),
                Prompt.body.ilike(f"%{q}%")
            )
        )
    
    # Order results
    if scope == "personal":
        prompts = query.order_by(Prompt.position).all()
    else:
        prompts = query.order_by(Prompt.updated_at.desc()).all()
    
    return [prompt_to_response(prompt, current_user.id, db) for prompt in prompts]

@app.post("/prompts", response_model=PromptResponse, status_code=201)
async def create_prompt(
    prompt_data: PromptCreate, 
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Create a new prompt"""
    # logging.info(f"[CREATE PROMPT] User: {current_user.email} | Title: {prompt_data.title[:50]}{'...' if len(prompt_data.title) > 50 else ''} | Tags: {prompt_data.tags}")
    now = datetime.now(timezone.utc).isoformat()
    
    prompt = Prompt(
        id=str(uuid.uuid4()),
        title=prompt_data.title,
        body=prompt_data.body,
        owner_id=current_user.id,
        position=0,  # Will be updated if needed
        created_at=now,
        updated_at=now
    )
    
    db.add(prompt)
    db.flush()  # Flush to get the ID before adding tags
    
    # Handle tags
    if prompt_data.tags:
        update_prompt_tags(db, prompt, prompt_data.tags)
    
    # Log prompt creation
    # log_action(db, current_user.id, "CREATE_PROMPT", prompt.id, f"Created prompt '{prompt.title}'")
    
    db.commit()
    db.refresh(prompt)
    
    # logging.info(f"[PROMPT CREATED] ID: {prompt.id} | User: {current_user.email}")
    return prompt_to_response(prompt, current_user.id, db)

@app.patch("/prompts/{prompt_id}", response_model=PromptResponse)
async def update_prompt(
    prompt_id: str, 
    prompt_update: PromptUpdate, 
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Update an existing prompt"""
    # logging.info(f"[UPDATE PROMPT] User: {current_user.email} | Prompt ID: {prompt_id} | Fields: {list(prompt_update.dict(exclude_unset=True).keys())}")
    prompt = db.query(Prompt).filter(
        and_(Prompt.id == prompt_id, Prompt.owner_id == current_user.id)
    ).first()
    
    if not prompt:
        # logging.warning(f"[UPDATE FAILED] Prompt not found or access denied | ID: {prompt_id} | User: {current_user.email}")
        raise HTTPException(status_code=404, detail="Prompt not found or you don't have permission")
    
    # Update fields
    update_data = prompt_update.dict(exclude_unset=True)
    
    # Track if content was actually changed
    content_changed = False
    
    # Handle tags separately
    if 'tags' in update_data:
        tags = update_data.pop('tags')
        update_prompt_tags(db, prompt, tags)
        content_changed = True
    
    # Handle starred field conversion (bool -> int for SQLite)
    # Note: starring doesn't count as content change
    if 'starred' in update_data:
        starred_value = update_data.pop('starred')
        prompt.starred = 1 if starred_value else 0
    
    # Update other fields and check if content changed
    for field, value in update_data.items():
        if hasattr(prompt, field):
            # Only title and body are considered content changes
            if field in ['title', 'body']:
                content_changed = True
            setattr(prompt, field, value)
    
    # Only update timestamp if content was actually changed
    if content_changed:
        prompt.updated_at = datetime.now(timezone.utc).isoformat()
    
    db.commit()
    db.refresh(prompt)
    
    return prompt_to_response(prompt, current_user.id, db)

@app.post("/prompts/{prompt_id}/share", response_model=Dict[str, Any])
async def share_prompt(
    prompt_id: str, 
    share_data: SharePayload,
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Share a prompt with specific users and/or departments"""
    # logging.info(f"[SHARE PROMPT] User: {current_user.email} | Prompt ID: {prompt_id} | Recipients: {len(share_data.user_ids)} users")
    prompt = db.query(Prompt).filter(
        and_(Prompt.id == prompt_id, Prompt.owner_id == current_user.id)
    ).first()
    
    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt not found or you don't have permission")
    
    # Get current timestamp for sharing
    shared_at = datetime.now(timezone.utc).isoformat()
    
    # Clear existing user shares for this prompt
    db.execute(prompt_user_shares.delete().where(prompt_user_shares.c.prompt_id == prompt_id))
    
    # Add new user shares with current timestamp (this ensures timestamp is always updated)
    for user_id in share_data.user_ids:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.execute(prompt_user_shares.insert().values(
                prompt_id=prompt_id, 
                user_id=user_id,
                shared_at=shared_at
            ))
    
    # Log sharing activity
    # logging.info(f"[PROMPT SHARED] ID: {prompt_id} | Title: {prompt.title[:30]}{'...' if len(prompt.title) > 30 else ''} | Shared with: {share_data.user_ids}")
    # log_action(db, current_user.id, "SHARE_PROMPT", prompt_id, 
    #           f"Shared prompt '{prompt.title}' with {len(share_data.user_ids)} users")
    
    db.commit()
    
    return {
        "message": "Prompt sharing updated successfully",
        "shared_with_users": len(share_data.user_ids)
    }

@app.post("/prompts/reorder", status_code=204)
async def reorder_prompts(
    payload: ReorderPayload, 
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Reorder user's prompts"""
    prompts = db.query(Prompt).filter(Prompt.owner_id == current_user.id).all()
    prompt_map = {p.id: p for p in prompts}

    if len(payload.ordered_ids) != len(prompt_map):
        raise HTTPException(status_code=400, detail="Mismatch in prompt count")

    for i, prompt_id in enumerate(payload.ordered_ids):
        if prompt_id in prompt_map:
            prompt_map[prompt_id].position = i

    db.commit()

@app.delete("/prompts/{prompt_id}", status_code=204)
async def delete_prompt(
    prompt_id: str, 
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Delete a prompt"""
    # logging.info(f"[DELETE PROMPT] User: {current_user.email} | Prompt ID: {prompt_id}")
    prompt = db.query(Prompt).filter(
        and_(Prompt.id == prompt_id, Prompt.owner_id == current_user.id)
    ).first()
    
    if not prompt:
        # logging.warning(f"[DELETE FAILED] Prompt not found or access denied | ID: {prompt_id} | User: {current_user.email}")
        raise HTTPException(status_code=404, detail="Prompt not found or you don't have permission")
    
    # Log before deletion (need title before object is deleted)
    # logging.info(f"[PROMPT DELETED] ID: {prompt_id} | Title: {prompt.title[:30]}{'...' if len(prompt.title) > 30 else ''} | User: {current_user.email}")
    # log_action(db, current_user.id, "DELETE_PROMPT", prompt_id, f"Deleted prompt '{prompt.title}'")
    
    db.delete(prompt)
    db.commit()

@app.post("/prompts/{prompt_id}/star", response_model=Dict[str, Any])
async def toggle_star_status(
    prompt_id: str,
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Toggle star status for any accessible prompt (owned OR shared)"""
    # Check if user can access this prompt
    prompt = get_prompt_if_accessible(prompt_id, current_user, db)
    if not prompt:
        # logging.warning(f"[STAR FAILED] Prompt not accessible | ID: {prompt_id} | User: {current_user.email}")
        raise HTTPException(status_code=404, detail="Prompt not found or you don't have access")
    
    # Check if user has already starred this prompt
    existing_star = db.query(UserStarredPrompt).filter(
        and_(
            UserStarredPrompt.user_id == current_user.id,
            UserStarredPrompt.prompt_id == prompt_id
        )
    ).first()
    
    if existing_star:
        # Unstar - remove the record
        db.delete(existing_star)
        starred = False
        action = "unstarred"
    else:
        # Star - create new record
        starred_at = datetime.now(timezone.utc).isoformat()
        new_star = UserStarredPrompt(
            user_id=current_user.id,
            prompt_id=prompt_id,
            starred_at=starred_at
        )
        db.add(new_star)
        starred = True
        action = "starred"
    
    db.commit()
    
    # logging.info(f"[STAR TOGGLE] User: {current_user.email} | Prompt: {prompt_id} | Action: {action}")
    return {
        "starred": starred,
        "action": action,
        "prompt_id": prompt_id,
        "user_id": current_user.id
    }

@app.get("/prompts/{prompt_id}/sharing", response_model=Dict[str, Any])
async def get_prompt_sharing(
    prompt_id: str,
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Get detailed sharing information for a prompt"""
    
    # Verify ownership
    prompt = db.query(Prompt).filter(
        and_(Prompt.id == prompt_id, Prompt.owner_id == current_user.id)
    ).first()
    
    if not prompt:
        raise HTTPException(404, "Prompt not found or you don't have permission")
    
    # Get user shares with shared_at timestamp
    user_shares = db.execute(text('''
        SELECT u.id, u.name, u.email, pus.shared_at
        FROM prompt_user_shares pus 
        JOIN users u ON pus.user_id = u.id 
        WHERE pus.prompt_id = :pid
        ORDER BY pus.shared_at DESC
    '''), {'pid': prompt_id}).fetchall()
    
    # Calculate totals
    total_recipients = len(user_shares)
    
    # Get the most recent shared_at timestamp for the entire sharing (latest re-share)
    most_recent_shared_at = user_shares[0].shared_at if user_shares else None
    
    return {
        "prompt": {
            "id": prompt.id,
            "title": prompt.title
        },
        "sharing": {
            "is_shared": total_recipients > 0,
            "total_recipients": total_recipients,
            "shared_at": most_recent_shared_at,  # Add the shared_at timestamp
            "users": [{"id": row.id, "name": row.name, "email": row.email, "shared_at": row.shared_at} for row in user_shares]
        }
    }

@app.delete("/prompts/{prompt_id}/sharing")
async def unshare_prompt(
    prompt_id: str,
    current_user: User = Depends(get_current_user_from_header),
    db: Session = Depends(get_db_session)
):
    """Remove all sharing for a prompt (make it private)"""
    
    # Verify ownership
    prompt = db.query(Prompt).filter(
        and_(Prompt.id == prompt_id, Prompt.owner_id == current_user.id)
    ).first()
    
    if not prompt:
        raise HTTPException(404, "Prompt not found or you don't have permission")
    
    # Remove all user shares
    db.execute(prompt_user_shares.delete().where(prompt_user_shares.c.prompt_id == prompt_id))
    
    db.commit()
    
    return {"message": "Prompt unshared successfully", "is_shared": False}

# Department sharing removed - individual user sharing only

@app.post("/set-password")
async def set_password(request: SetPasswordRequest, db: Session = Depends(get_db_session)):
    """Set password for a user account"""
    # logging.info(f"[SET PASSWORD] Email: {request.email}")
    email_lower = request.email.lower().strip()
    
    # Find user by email
    user = db.query(User).filter(User.email.ilike(email_lower)).first()
    if not user:
        # logging.warning(f"[PASSWORD SET FAILED] User not found: {email_lower}")
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if password already exists
    if user.password_hash is not None:
        # logging.warning(f"[PASSWORD SET FAILED] Password already exists for: {user.email}")
        raise HTTPException(status_code=409, detail="Password has already been set for this account")
    
    # Hash and set the password
    hashed_password = hash_password(request.password)
    user.password_hash = hashed_password
    
    # Log the action
    # logging.info(f"[PASSWORD SET SUCCESS] User: {user.email} | ID: {user.id}")
    # log_action(db, user.id, "SET_PASSWORD", str(user.id), f"Password set for user {user.email}")
    
    db.commit()
    
    return {"message": "Password set successfully"}

@app.post("/login")
async def login(request: AuthLoginRequest, db: Session = Depends(get_db_session)):
    """Authenticate user with email and password"""
    # logging.info(f"[AUTH LOGIN] Email: {request.email}")
    email_lower = request.email.lower().strip()
    hashed_password = hash_password(request.password)
    
    # Execute JOIN query to get user with department information
    user = db.query(User).join(Department, User.department_id == Department.id, isouter=True)\
             .filter(User.email.ilike(email_lower))\
             .filter(User.password_hash == hashed_password)\
             .first()
    
    if not user:
        # logging.warning(f"[AUTH LOGIN FAILED] Invalid credentials for: {email_lower}")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Log successful login
    # logging.info(f"[AUTH LOGIN SUCCESS] User: {user.email} | ID: {user.id} | Department: {user.department.name if user.department else 'None'}")
    # log_action(db, user.id, "LOGIN", str(user.id), f"User {user.email} logged in successfully")
    # db.commit()
    
    # Return user ID as auth token and user details (matching prototype-login format)
    return {
        "access_token": str(user.id),  # User ID as token
        "user_details": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "department_id": user.department_id,
            "department_name": user.department.name if user.department else None
        }
    }

# @app.get("/logs")
# async def get_logs(
#     limit: int = 50,
#     action: str = None,
#     current_user: User = Depends(get_current_user_from_header),
#     db: Session = Depends(get_db_session)
# ):
#     """Get recent log entries"""
#     query = db.query(LogEntry)
    
#     # Filter by action if specified
#     if action:
#         query = query.filter(LogEntry.action == action)
    
#     # For now, return all logs (in production, might want to restrict to user's own logs)
#     logs = query.order_by(LogEntry.timestamp.desc()).limit(limit).all()
    
#     return [
#         {
#             "id": log.id,
#             "timestamp": log.timestamp,
#             "level": log.level,
#             "user_id": log.user_id,
#             "user_name": log.user.name if log.user else None,
#             "action": log.action,
#             "resource_id": log.resource_id,
#             "message": log.message
#         }
#         for log in logs
#     ]

if __name__ == "__main__":
    import uvicorn
    # uvicorn.run(app, host="127.0.0.1", port=8000)
    # uvicorn.run(app, host="10.10.12.6", port=8009)
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)