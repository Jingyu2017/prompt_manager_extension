import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, Table, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from contextlib import contextmanager

DATABASE_URL = "sqlite:///prompt_manager.db"

# SQLAlchemy setup
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Junction tables for many-to-many relationships
prompt_user_shares = Table(
    'prompt_user_shares',
    Base.metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('prompt_id', String, ForeignKey('prompts.id', ondelete='CASCADE')),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE')),
    Column('shared_at', String, nullable=False),  # ISO timestamp when shared
    UniqueConstraint('prompt_id', 'user_id', name='_prompt_user_share_uc')
)

# Department sharing removed - using individual user sharing only

prompt_tags = Table(
    'prompt_tags',
    Base.metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('prompt_id', String, ForeignKey('prompts.id', ondelete='CASCADE')),
    Column('tag_id', Integer, ForeignKey('tags.id', ondelete='CASCADE')),
    UniqueConstraint('prompt_id', 'tag_id', name='_prompt_tag_uc')
)

# User starred prompts table for per-user starring
class UserStarredPrompt(Base):
    __tablename__ = "user_starred_prompts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete='CASCADE'), nullable=False)
    prompt_id = Column(String, ForeignKey("prompts.id", ondelete='CASCADE'), nullable=False)
    starred_at = Column(String, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="starred_prompts")
    prompt = relationship("Prompt", back_populates="starred_by_users")
    
    __table_args__ = (
        UniqueConstraint('user_id', 'prompt_id', name='_user_prompt_star_uc'),
    )

# SQLAlchemy Models
class Department(Base):
    __tablename__ = "departments"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    
    # Relationships
    users = relationship("User", back_populates="department")

class Tag(Base):
    __tablename__ = "tags"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    
    # Relationships
    prompts = relationship("Prompt", secondary=prompt_tags, back_populates="tags")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password_hash = Column(String)
    department_id = Column(Integer, ForeignKey("departments.id"))
    
    # Relationships
    department = relationship("Department", back_populates="users")
    owned_prompts = relationship("Prompt", back_populates="owner")
    shared_prompts = relationship("Prompt", secondary=prompt_user_shares, back_populates="shared_with_users")
    starred_prompts = relationship("UserStarredPrompt", back_populates="user")

class Prompt(Base):
    __tablename__ = "prompts"
    
    id = Column(String, primary_key=True)  # Using UUIDs from Python
    title = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    position = Column(Integer, default=0)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="owned_prompts")
    shared_with_users = relationship("User", secondary=prompt_user_shares, back_populates="shared_prompts")
    tags = relationship("Tag", secondary=prompt_tags, back_populates="prompts")
    starred_by_users = relationship("UserStarredPrompt", back_populates="prompt", cascade="all, delete-orphan")

class LogEntry(Base):
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String, nullable=False)      # ISO format
    level = Column(String, nullable=False)          # INFO, ERROR
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False)         # CREATE_PROMPT, SHARE_PROMPT, etc
    resource_id = Column(String)                   # prompt ID, user ID, etc  
    message = Column(Text, nullable=False)          # Human readable description
    
    # Relationships
    user = relationship("User")

# Database utilities
def init_database():
    """Initialize the database and create all tables"""
    Base.metadata.create_all(bind=engine)

@contextmanager
def get_db():
    """Context manager for database sessions"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_db_session():
    """Get a database session (for dependency injection)"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Raw SQL setup function (for initial creation if needed)
def setup_database_schema():
    """Setup database schema using raw SQL (backup method)"""
    conn = sqlite3.connect("prompt_manager.db")
    cursor = conn.cursor()
    
    # Create tables
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            department_id INTEGER,
            FOREIGN KEY (department_id) REFERENCES departments (id)
        );

        CREATE TABLE IF NOT EXISTS prompts (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            position INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS prompt_user_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (prompt_id) REFERENCES prompts (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE(prompt_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS prompt_department_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_id TEXT NOT NULL,
            department_id INTEGER NOT NULL,
            FOREIGN KEY (prompt_id) REFERENCES prompts (id) ON DELETE CASCADE,
            FOREIGN KEY (department_id) REFERENCES departments (id) ON DELETE CASCADE,
            UNIQUE(prompt_id, department_id)
        );

        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS prompt_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_id TEXT NOT NULL,
            tag_id INTEGER NOT NULL,
            FOREIGN KEY (prompt_id) REFERENCES prompts (id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE,
            UNIQUE(prompt_id, tag_id)
        );

        CREATE TABLE IF NOT EXISTS user_starred_prompts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            prompt_id TEXT NOT NULL,
            starred_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (prompt_id) REFERENCES prompts (id) ON DELETE CASCADE,
            UNIQUE(user_id, prompt_id)
        );
    """)
    
    conn.commit()
    conn.close()