import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Float, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# ----------------- Config -----------------
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

DATA_DIR = os.path.abspath(os.getenv("DATA_DIR", "./data"))
MEDIA_DIR = os.path.join(DATA_DIR, "media")
AVATAR_DIR = os.path.join(DATA_DIR, "avatars")
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(AVATAR_DIR, exist_ok=True)

# ----------------- Models -----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="consumer")  # consumer | creator | admin
    created_at = Column(DateTime, default=datetime.utcnow)

class Video(Base):
    __tablename__ = "videos"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    publisher = Column(String, nullable=True)
    producer = Column(String, nullable=True)
    genre = Column(String, nullable=True)
    age_rating = Column(String, nullable=True)
    filename = Column(String, nullable=True)   # if uploaded to local storage
    url = Column(String, nullable=True)        # external URL (seed/demo)
    created_at = Column(DateTime, default=datetime.utcnow)
    comments = relationship("Comment", back_populates="video", cascade="all,delete-orphan")
    ratings = relationship("Rating", back_populates="video", cascade="all,delete-orphan")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    video_id = Column(Integer, ForeignKey("videos.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    video = relationship("Video", back_populates="comments")

class Rating(Base):
    __tablename__ = "ratings"
    id = Column(Integer, primary_key=True)
    video_id = Column(Integer, ForeignKey("videos.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    score = Column(Integer, nullable=False)  # 1..5
    created_at = Column(DateTime, default=datetime.utcnow)
    video = relationship("Video", back_populates="ratings")

Base.metadata.create_all(bind=engine)

# ----------------- Auth helpers -----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----------------- Schemas -----------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Signup(BaseModel):
    username: str
    password: str
    role: Optional[str] = "consumer"

class Login(BaseModel):
    username: str
    password: str

class Me(BaseModel):
    id: int
    username: str
    role: str

class VideoOut(BaseModel):
    id: int
    title: str
    publisher: Optional[str] = None
    producer: Optional[str] = None
    genre: Optional[str] = None
    age_rating: Optional[str] = None
    filename: Optional[str] = None
    url: Optional[str] = None

class CommentOut(BaseModel):
    id: int
    text: str

class RatingOut(BaseModel):
    average: float
    count: int

# ----------------- FastAPI -----------------
app = FastAPI(title="Vibluna API")

origins = os.getenv("CORS_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins.split(",")] if origins != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static mounts (serve uploaded media & avatars)
if not os.path.exists(MEDIA_DIR):
    os.makedirs(MEDIA_DIR, exist_ok=True)
if not os.path.exists(AVATAR_DIR):
    os.makedirs(AVATAR_DIR, exist_ok=True)

app.mount("/media", StaticFiles(directory=MEDIA_DIR), name="media")
app.mount("/avatars", StaticFiles(directory=AVATAR_DIR), name="avatars")

# ----------------- Utils -----------------
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
security = HTTPBearer()

def get_current_user(db: Session = Depends(get_db), creds: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = creds.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ----------------- Routes -----------------
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.post("/signup", response_model=Me)
def signup(payload: Signup, db: Session = Depends(get_db)):
    if not payload.username or not payload.password:
        raise HTTPException(400, "username and password required")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(409, "username already exists")
    # Enforce consumer-only signup via API
    role = "consumer"
    user = User(username=payload.username, password_hash=get_password_hash(payload.password), role=role)
    db.add(user); db.commit(); db.refresh(user)
    return Me(id=user.id, username=user.username, role=user.role)

@app.post("/login", response_model=Token)
def login(payload: Login, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "invalid credentials")
    token = create_access_token({"sub": user.username})
    return Token(access_token=token)

@app.get("/me", response_model=Me)
def get_me(me: User = Depends(get_current_user)):
    return Me(id=me.id, username=me.username, role=me.role)

@app.post("/me/avatar")
async def upload_avatar(file: UploadFile = File(...), me: User = Depends(get_current_user)):
    # Save avatar with user id + original extension
    ext = os.path.splitext(file.filename or "")[1].lower() or ".png"
    if ext not in [".png", ".jpg", ".jpeg", ".webp"]:
        ext = ".png"
    out_path = os.path.join(AVATAR_DIR, f"{me.id}{ext}")
    data = await file.read()
    with open(out_path, "wb") as f:
        f.write(data)
    return {"url": f"/avatars/{me.id}{ext}"}

# --------- Video endpoints ---------
@app.get("/videos/latest", response_model=List[VideoOut])
def videos_latest(db: Session = Depends(get_db)):
    rows = db.query(Video).order_by(Video.created_at.desc()).limit(50).all()
    return [VideoOut(
        id=v.id, title=v.title, publisher=v.publisher, producer=v.producer, genre=v.genre,
        age_rating=v.age_rating, filename=v.filename, url=v.url
    ) for v in rows]

@app.get("/videos/search", response_model=List[VideoOut])
def videos_search(q: Optional[str] = None, db: Session = Depends(get_db)):
    if not q:
        return videos_latest(db)
    ql = f"%{q.lower()}%"
    rows = db.query(Video).filter(
        (Video.title.ilike(ql)) | (Video.publisher.ilike(ql)) | (Video.producer.ilike(ql)) | (Video.genre.ilike(ql))
    ).order_by(Video.created_at.desc()).limit(50).all()
    return [VideoOut(id=v.id, title=v.title, publisher=v.publisher, producer=v.producer, genre=v.genre,
                     age_rating=v.age_rating, filename=v.filename, url=v.url) for v in rows]

@app.post("/videos/upload", response_model=VideoOut)
async def upload_video(
    title: str = Form(...),
    publisher: Optional[str] = Form(None),
    producer: Optional[str] = Form(None),
    genre: Optional[str] = Form(None),
    age_rating: Optional[str] = Form(None),
    file: UploadFile = File(...),
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if me.role.lower() != "creator" and me.role.lower() != "admin":
        raise HTTPException(403, "creator role required")
    # Save file
    safe_name = f"{int(datetime.utcnow().timestamp())}_{file.filename.replace(' ', '_')}"
    out_path = os.path.join(MEDIA_DIR, safe_name)
    data = await file.read()
    with open(out_path, "wb") as f:
        f.write(data)
    v = Video(title=title, publisher=publisher, producer=producer, genre=genre, age_rating=age_rating, filename=safe_name)
    db.add(v); db.commit(); db.refresh(v)
    return VideoOut(id=v.id, title=v.title, publisher=v.publisher, producer=v.producer, genre=v.genre, age_rating=v.age_rating, filename=v.filename, url=v.url)

@app.post("/videos/{video_id}/comment")
def add_comment(video_id: int, payload: dict, me: User = Depends(get_current_user), db: Session = Depends(get_db)):
    text = (payload or {}).get("text", "").strip()
    if not text:
        raise HTTPException(400, "text required")
    v = db.query(Video).get(video_id)
    if not v: raise HTTPException(404, "video not found")
    c = Comment(video_id=video_id, user_id=me.id, text=text)
    db.add(c); db.commit(); db.refresh(c)
    return {"id": c.id, "ok": True}

@app.get("/videos/{video_id}/comments", response_model=List[CommentOut])
def list_comments(video_id: int, db: Session = Depends(get_db)):
    rows = db.query(Comment).filter(Comment.video_id == video_id).order_by(Comment.created_at.desc()).limit(50).all()
    return [CommentOut(id=r.id, text=r.text) for r in rows]

@app.post("/videos/{video_id}/rate")
def rate_video(video_id: int, payload: dict, me: User = Depends(get_current_user), db: Session = Depends(get_db)):
    score = int((payload or {}).get("score", 0))
    if score < 1 or score > 5:
        raise HTTPException(400, "score must be 1..5")
    v = db.query(Video).get(video_id)
    if not v: raise HTTPException(404, "video not found")
    r = Rating(video_id=video_id, user_id=me.id, score=score)
    db.add(r); db.commit(); db.refresh(r)
    return {"id": r.id, "ok": True}

@app.get("/videos/{video_id}/rating", response_model=RatingOut)
def get_rating(video_id: int, db: Session = Depends(get_db)):
    rows = db.query(Rating).filter(Rating.video_id == video_id).all()
    if not rows:
        return RatingOut(average=0.0, count=0)
    avg = sum(r.score for r in rows) / len(rows)
    return RatingOut(average=avg, count=len(rows))

# --------- Dev seed (optional) ---------
@app.post("/dev/seed")
def dev_seed(db: Session = Depends(get_db)):
    if os.getenv("ALLOW_DEV_SEED", "false").lower() != "true":
        raise HTTPException(403, "dev seed disabled")
    samples = [
        dict(title="Demo Launch", publisher="You", producer="You", genre="Promo", age_rating="PG", url="https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"),
        dict(title="Campus Vibes", publisher="Studio X", producer="Mia K.", genre="Music", age_rating="PG", url="https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4"),
        dict(title="Quick Python Tips", publisher="DevDaily", producer="A. Rahman", genre="Education", age_rating="G", url="https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4"),
        dict(title="Standup Night", publisher="LaughHub", producer="Jay P.", genre="Comedy", age_rating="PG-13", url="https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/TearsOfSteel.mp4"),
    ]
    added = 0
    for s in samples:
        v = Video(**s)
        db.add(v); added += 1
    # Ensure demo users
    if not db.query(User).filter(User.username=="admin").first():
        db.add(User(username="admin", password_hash=get_password_hash("Pass123!"), role="admin"))
    if not db.query(User).filter(User.username=="creator_demo").first():
        db.add(User(username="creator_demo", password_hash=get_password_hash("Pass123!"), role="creator"))
    if not db.query(User).filter(User.username=="consumer_demo").first():
        db.add(User(username="consumer_demo", password_hash=get_password_hash("Pass123!"), role="consumer"))
    db.commit()
    return {"ok": True, "videos_added": added}
