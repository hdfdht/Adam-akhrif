package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	ctx = context.Background()

	mongoURI  = os.Getenv("MONGODB_URI")
	redisAddr = os.Getenv("REDIS_ADDR")
	redisPass = os.Getenv("REDIS_PASSWORD")
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	aesKeyB64 = os.Getenv("AES_KEY_BASE64")
	aesKey    []byte

	mongoCli *mongo.Client
	db       *mongo.Database
	redisCli *redis.Client

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	clients   = make(map[*websocket.Conn]string) // websocket clients map: conn => username
	clientsMu sync.Mutex
)

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username     string             `bson:"username" json:"username"`
	PasswordHash string             `bson:"password_hash,omitempty" json:"-"`
	Email        string             `bson:"email,omitempty" json:"email,omitempty"`
	Phone        string             `bson:"phone,omitempty" json:"phone,omitempty"`
	Roles        []string           `bson:"roles" json:"roles"`
	Points       int                `bson:"points" json:"points"`
	Telegram     string             `bson:"telegram,omitempty" json:"telegram,omitempty"`
	Discord      string             `bson:"discord,omitempty" json:"discord,omitempty"`
	Instagram    string             `bson:"instagram,omitempty" json:"instagram,omitempty"`
	Twitter      string             `bson:"twitter,omitempty" json:"twitter,omitempty"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	LastActive   time.Time          `bson:"last_active" json:"last_active"`
}

type Message struct {
	ID         primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	SenderID   primitive.ObjectID  `bson:"sender_id" json:"sender_id"`
	Username   string              `bson:"username" json:"username"` // sender username for easier broadcast
	Content    string              `bson:"content" json:"content"`
	MediaType  string              `bson:"media_type,omitempty" json:"media_type,omitempty"`
	MediaURL   string              `bson:"media_url,omitempty" json:"media_url,omitempty"`
	Timestamp  time.Time           `bson:"timestamp" json:"timestamp"`
	Deleted    bool                `bson:"deleted" json:"deleted"`
	ReplyTo    *primitive.ObjectID `bson:"reply_to,omitempty" json:"reply_to,omitempty"`
	IsFiltered bool                `bson:"is_filtered" json:"is_filtered"`
}

// AES-GCM encryption / decryption helpers
func encryptAESGCM(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func decryptAESGCM(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// JWT Claims with roles + username + userID
type CustomClaims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// Generate JWT with 24h expiry (قوي وآمن)
func generateJWT(userID, username string, roles []string) (string, error) {
	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "mega-chat-pro",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateJWT(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// Middleware: تحقق من التوثيق والاضافة لـ Context
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateJWT(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Register endpoint مع تحقق صارم + تنظيف المدخلات + تسجيل المستخدم
func registerHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Username  string `json:"username"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		Telegram  string `json:"telegram,omitempty"`
		Discord   string `json:"discord,omitempty"`
		Instagram string `json:"instagram,omitempty"`
		Twitter   string `json:"twitter,omitempty"`
	}
	var body req
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Validation minimal
	if len(body.Username) < 3 || len(body.Password) < 6 {
		http.Error(w, "username must be >=3 chars and password >=6 chars", http.StatusBadRequest)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	body.Email = strings.TrimSpace(body.Email)

	usersCol := db.Collection("users")
	count, err := usersCol.CountDocuments(ctx, bson.M{"username": body.Username})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "username already taken", http.StatusConflict)
		return
	}

	passHash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "server error hashing password", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	user := User{
		Username:     body.Username,
		Email:        body.Email,
		PasswordHash: string(passHash),
		Roles:        []string{"User"},
		Points:       0,
		Telegram:     body.Telegram,
		Discord:      body.Discord,
		Instagram:    body.Instagram,
		Twitter:      body.Twitter,
		CreatedAt:    now,
		LastActive:   now,
	}

	res, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true,
		"id": res.InsertedID,
	})
}

// Login endpoint + تحديث آخر نشاط واص// Login endpoint + تحديث آخر نشاط واص// Login endpoint + تحديث آخر نشاط واص// Login endpoint + تحديث آخر نشاط واص	
	// Login endpoint + تحديث آخر نشاط واص
	# dragon_ultra_real_auto.py
# Self-Improving (Real) Server: FastAPI + Git (branch/commit/push) + GitHub PR + Docker/pytest sandbox
# ملاحظات تشغيل:
# 1) صايب .env أو استعمل متغيرات البيئة التالية:
#    GITHUB_TOKEN=<token with repo scope>
#    GITHUB_REPO=<owner/repo>  مثال:  myuser/myrepo
#    GIT_AUTHOR_NAME="DragonBot"  GIT_AUTHOR_EMAIL="dragon@local"
#    WORK_DIR=/tmp/dragon-work    (مسار مؤقت للـ clone)
#    PYTEST_IMAGE=python:3.11     (صورة Docker فيها pytest أو كيتنصب داخله)
#    PYTEST_CMD="pytest -q"       (أمر الاختبارات)
# 2) لازم تكون آلة فيها git و docker مفعّلين وعندك صلاحيات.
# 3) هاد السيرفر كيدير:
#    - اقتراح تحسينات (diff) من prompt أو ملف patch مرفوع
#    - إنشاء فرع، تطبيق الـ diff، تشغيل اختبارات داخل Docker، وخلق PR أوتوماتيكياً إذا نجحات الاختبارات
#    - كل العمليات متسجلة فقاعدة البيانات + Logs
# 4) ما كيدير حتى تعديل مباشر للمين، غير عبر PR (هادي أحسن ممارسة واقعية).

import os, io, sys, json, secrets, logging, hashlib, random, shutil, subprocess, textwrap
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr, validator
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import jwt
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# ================== إعدادات ==================
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(64)
ALGO = "HS512"
TOKEN_MIN = int(os.getenv("ACCESS_TOKEN_MIN", "60"))
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./dragon_real.db")
LOG_FILE = os.getenv("LOG_FILE", "dragon_real.log")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO  = os.getenv("GITHUB_REPO")     # "owner/repo"
WORK_DIR     = os.getenv("WORK_DIR", "/tmp/dragon-work")
PYTEST_IMAGE = os.getenv("PYTEST_IMAGE", "python:3.11")
PYTEST_CMD   = os.getenv("PYTEST_CMD", "pytest -q")
GIT_AUTHOR_NAME  = os.getenv("GIT_AUTHOR_NAME", "DragonBot")
GIT_AUTHOR_EMAIL = os.getenv("GIT_AUTHOR_EMAIL", "dragon@local")

os.makedirs(WORK_DIR, exist_ok=True)

# ================== لوجات ==================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("DragonReal")

# ================== DB ==================
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if "sqlite" in DB_URL else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__="users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(20), default="user")  # user/admin
    disabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    queries = relationship("AIQuery", back_populates="user", cascade="all, delete-orphan")

class AIQuery(Base):
    __tablename__="ai_queries"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="queries")

class Proposal(Base):
    __tablename__="proposals"
    id = Column(Integer, primary_key=True)
    title = Column(String(150), nullable=False)
    description = Column(Text, nullable=False)
    diff_text = Column(Text, nullable=False)  # unified diff أو patch
    branch = Column(String(200), nullable=True)
    pr_number = Column(Integer, nullable=True)
    status = Column(String(20), default="pending")  # pending/tested/failed/pr_opened/merged/rejected
    sandbox_log = Column(Text, nullable=True)
    created_by = Column(String(50), nullable=False)   # username
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ================== أمان & API ==================
app = FastAPI(title="Dragon Ultra -- Real Self‑Improving (Guarded via PR)")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["Authorization","Content-Type"], allow_credentials=True
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd = CryptContext(schemes=["argon2","bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, regex=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(..., min_length=12)
    role: Optional[str] = "user"
    @validator("password")
    def strong(cls, v):
        if not any(c.isupper() for c in v): raise ValueError("Password needs uppercase")
        if not any(c.isdigit() for c in v): raise ValueError("Password needs digit")
        if not any(c in "!@#$%^&*()-_+=" for c in v): raise ValueError("Password needs symbol")
        return v

class UserRead(BaseModel):
    id:int; username:str; email:EmailStr; role:str; disabled:bool
    class Config: orm_mode=True

class Token(BaseModel):
    access_token:str; token_type:str

class AIReq(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=8000)

class ProposalCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=150)
    description: str = Field(..., min_length=5)
    diff_text: str = Field(..., min_length=10)  # خاص يكون patch حقيقي

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def hash_pw(p:str)->str: return pwd.hash(p)
def verify_pw(p:str,h:str)->bool: return pwd.verify(p,h)

def create_token(data:dict, minutes:int=TOKEN_MIN)->str:
    to_encode=data.copy(); to_encode.update({"exp": datetime.utcnow()+timedelta(minutes=minutes)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGO)

def current_user(token:str=Depends(oauth2_scheme), db:Session=Depends(get_db))->User:
    try:
        payload=jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
        uname=payload.get("sub"); 
        if not uname: raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    u=db.query(User).filter(User.username==uname).first()
    if not u or u.disabled: raise HTTPException(status_code=403, detail="User disabled/not found")
    return u

def require_admin(u:User):
    if u.role!="admin": raise HTTPException(status_code=403, detail="Admin only")

# ================== أدوات Git/Docker واقعية ==================
def run(cmd:list, cwd:Optional[str]=None, env:Optional[dict]=None)->(int,str,str):
    p = subprocess.Popen(cmd, cwd=cwd, env=env or os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def git_clone_or_pull(target_dir:str, repo:str, token:str)->None:
    if os.path.isdir(os.path.join(target_dir, ".git")):
        code, out, err = run(["git","fetch","--all"], cwd=target_dir)
        if code!=0: raise RuntimeError(f"git fetch failed: {err}")
        run(["git","checkout","main"], cwd=target_dir)
        run(["git","pull","origin","main"], cwd=target_dir)
    else:
        # نستعمل https مع التوكن
        url=f"https://{token}:x-oauth-basic@github.com/{repo}.git"
        code, out, err = run(["git","clone",url,target_dir])
        if code!=0: raise RuntimeError(f"git clone failed: {err}")

def git_new_branch(work:str, branch:str)->None:
    run(["git","checkout","main"], cwd=work)
    code, out, err = run(["git","checkout","-b",branch], cwd=work)
    if code!=0 and "already exists" not in err.lower(): raise RuntimeError(f"git branch failed: {err}")

def apply_patch(work:str, diff_text:str)->None:
    # نطبّق patch عبر "git apply -p0"
    patch_path=os.path.join(work,"dragon_patch.diff")
    with open(patch_path,"w",encoding="utf-8") as f: f.write(diff_text)
    code, out, err = run(["git","apply","--whitespace=fix",patch_path], cwd=work)
    if code!=0: raise RuntimeError(f"git apply failed: {err}")

def git_commit_push(work:str, branch:str, message:str, token:str, repo:str)->None:
    env=os.environ.copy()
    env["GIT_AUTHOR_NAME"]=GIT_AUTHOR_NAME; env["GIT_AUTHOR_EMAIL"]=GIT_AUTHOR_EMAIL
    env["GIT_COMMITTER_NAME"]=GIT_AUTHOR_NAME; env["GIT_COMMITTER_EMAIL"]=GIT_AUTHOR_EMAIL
    run(["git","add","-A"], cwd=work, env=env)
    code, out, err = run(["git","commit","-m",message], cwd=work, env=env)
    if code!=0 and "nothing to commit" not in out.lower()+err.lower():
        raise RuntimeError(f"git commit failed: {err}")
    # push
    url=f"https://{token}:x-oauth-basic@github.com/{repo}.git"
    code, out, err = run(["git","push","-u",url,branch], cwd=work, env=env)
    if code!=0: raise RuntimeError(f"git push failed: {err}")

def docker_run_pytest(work:str)->str:
    """
    كنشغلو pytest داخل Docker رسمي.
    - كنركّب سورس الريبو داخل الكونتينر read-write
    - إلا ماكانش pytest فالصورة، نقدرو نسبطوه بسرعة
    """
    test_script = textwrap.dedent(f"""
        set -e
        python -m pip install --upgrade pip >/dev/null 2>&1 || true
        python -m pip install pytest >/dev/null 2>&1 || true
        {PYTEST_CMD}
    """).strip()
    cmd=[
        "docker","run","--rm",
        "-v",f"{work}:/work",
        "-w","/work",
        PYTEST_IMAGE,
        "bash","-lc", test_script
    ]
    code, out, err = run(cmd)
    log = f"[Docker pytest] code={code}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
    if code!=0: raise RuntimeError(log)
    return log

def github_open_pr(token:str, repo:str, branch:str, title:str, body:str)->int:
    import requests
    url=f"https://api.github.com/repos/{repo}/pulls"
    headers={"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json"}
    payload={"title":title, "head":branch, "base":"main", "body":body}
    r=requests.post(url, headers=headers, json=payload, timeout=60)
    if r.status_code not in (200,201):
        raise RuntimeError(f"PR create failed: {r.status_code} {r.text}")
    return r.json().get("number")

# ================== Endpoints ==================
@app.post("/users/", response_model=UserRead)
@limiter.limit("5/minute")
def create_user(body:UserCreate, db:Session=Depends(get_db)):
    if db.query(User).filter((User.username==body.username)|(User.email==body.email)).first():
        raise HTTPException(400, "username/email exists")
    u=User(username=body.username, email=body.email, hashed_password=hash_pw(body.password), role=body.role)
    db.add(u); db.commit(); db.refresh(u); return u

@app.post("/token", response_model=Token)
@limiter.limit("10/minute")
def login(form:OAuth2PasswordRequestForm=Depends(), db:Session=Depends(get_db)):
    u=db.query(User).filter(User.username==form.username).first()
    if not u or not verify_pw(form.password, u.hashed_password):
        raise HTTPException(400, "bad credentials")
    if u.disabled: raise HTTPException(403, "user disabled")
    tok=create_token({"sub":u.username,"role":u.role})
    return {"access_token":tok,"token_type":"bearer"}

@app.post("/ai/chat")
@limiter.limit("20/minute")
def ai_chat(req:AIReq, user:User=Depends(current_user), db:Session=Depends(get_db)):
    # مولّد بسيط (حقيقي، بلا API خارجي) باش الرد يكون محدد
    seed = int(hashlib.sha256(req.prompt.encode()).hexdigest(),16)%10**8
    random.seed(seed)
    ideas = ["خطة اختبار","تنظيف كود","تحسين توثيق","قياس أداء","تقليل زمن الاستجابة","تغطية وحدات"]
    resp = f"فكرة عملية: {random.choice(ideas)} بناء على سؤالك."
    q=AIQuery(user_id=user.id, prompt=req.prompt, response=resp)
    db.add(q); db.commit()
    return {"response":resp}

@app.post("/improve/propose", response_model=dict)
@limiter.limit("10/minute")
def propose_improvement(body:ProposalCreate, user:User=Depends(current_user), db:Session=Depends(get_db)):
    if not GITHUB_TOKEN or not GITHUB_REPO:
        raise HTTPException(500, "Configure GITHUB_TOKEN & GITHUB_REPO")
    pr = Proposal(
        title=body.title,
        description=body.description,
        diff_text=body.diff_text,
        status="pending",
        created_by=user.username
    )
    db.add(pr); db.commit(); db.refresh(pr)
    return {"id":pr.id, "status":pr.status}

@app.post("/improve/{proposal_id}/test-and-pr", response_model=dict)
@limiter.limit("5/minute")
def test_and_open_pr(proposal_id:int, user:User=Depends(current_user), db:Session=Depends(get_db)):
    # أي مستخدم يقدر يطلق العملية، ولكن الاندماج كيبقى عبر PR فقط
    if not GITHUB_TOKEN or not GITHUB_REPO:
        raise HTTPException(500, "Configure GITHUB_TOKEN & GITHUB_REPO")
    prop = db.query(Proposal).filter(Proposal.id==proposal_id).first()
    if not prop: raise HTTPException(404, "proposal not found")
    # 1) clone/pull
    work = os.path.join(WORK_DIR, f"repo_{proposal_id}")
    if os.path.isdir(work): shutil.rmtree(work)
    git_clone_or_pull(work, GITHUB_REPO, GITHUB_TOKEN)
    # 2) new branch
    branch = f"dragon/{proposal_id}-{hashlib.md5(prop.title.encode()).hexdigest()[:6]}"
    git_new_branch(work, branch)
    # 3) apply patch
    try:
        apply_patch(work, prop.diff_text)
    except Exception as e:
        prop.status="failed"; prop.sandbox_log=str(e); db.commit()
        raise HTTPException(400, f"patch failed: {e}")
    # 4) run tests in docker
    try:
        log_txt = docker_run_pytest(work)
        prop.sandbox_log = log_txt
        prop.status = "tested"
    except Exception as e:
        prop.sandbox_log = str(e)
        prop.status = "failed"
        db.commit()
        raise HTTPException(400, f"tests failed: {e}")
    # 5) commit + push
    try:
        git_commit_push(work, branch, f"[Dragon] {prop.title}", GITHUB_TOKEN, GITHUB_REPO)
    except Exception as e:
        prop.status="failed"; prop.sandbox_log += f"\nPUSH_ERR: {e}"
        db.commit(); raise HTTPException(400, f"push failed: {e}")
    # 6) create PR
    try:
        pr_number = github_open_pr(GITHUB_TOKEN, GITHUB_REPO, branch, prop.title, prop.description)
        prop.pr_number = pr_number
        prop.branch = branch
        prop.status = "pr_opened"
        db.commit()
    except Exception as e:
        prop.status="failed"; prop.sandbox_log += f"\nPR_ERR: {e}"
        db.commit(); raise HTTPException(400, f"pr failed: {e}")
    return {"id":prop.id, "status":prop.status, "branch":branch, "pr":prop.pr_number}

@app.get("/improve/list", response_model=List[dict])
@limiter.limit("20/minute")
def list_props(user:User=Depends(current_user), db:Session=Depends(get_db)):
    rows = db.query(Proposal).order_by(Proposal.created_at.desc()).all()
    return [
        {"id":r.id,"title":r.title,"status":r.status,"pr":r.pr_number,"created_by":r.created_by,"created_at":r.created_at.isoformat()}
        for r in rows
    ]

@app.post("/improve/{proposal_id}/reject", response_model=dict)
@limiter.limit("5/minute")
def reject_prop(proposal_id:int, user:User=Depends(current_user), db:Session=Depends(get_db)):
    require_admin(user)
    r=db.query(Proposal).filter(Proposal.id==proposal_id).first()
    if not r: raise HTTPException(404,"not found")
    r.status="rejected"; db.commit()
    return {"id":r.id,"status":r.status}

@app.get("/health")
def health():
    return {"ok":True,"ts":datetime.utcnow().isoformat()}

# ============== جدولة اقتراحات تلقائية (حقيقية ولكن بسيطة) ==============
scheduler = AsyncIOScheduler()

@scheduler.scheduled_job("interval", minutes=60)
def periodic_suggest():
    # كيولّد diff بسيط حقيقي على ملف README.md (مثال) -- تغييرات طفيفة (safe)
    if not (GITHUB_TOKEN and GITHUB_REPO): 
        log.warning("No GitHub env; skip periodic suggestion"); return
    title="وثيقة: تحديث بسيط لREADME"
    desc="تحسين وصف المشروع بإضافة قسم صغير للأهداف."
    diff = textwrap.dedent("""\
        diff --git a/README.md b/README.md
        index e69de29..b1f3a1b 100644
        --- a/README.md
        +++ b/README.md
        @@
        +## أهداف
        +- تحسين الموثوقية
        +- توسيع الاختبارات
        +- تسريع التطوير الآمن
    """)
    with SessionLocal() as db:
        p = Proposal(title=title, description=desc, diff_text=diff, status="pending", created_by="auto")
        db.add(p); db.commit()
        log.info(f"[scheduler] proposal #{p.id} created")

scheduler.start()

# ============== تشغيل محلّي ==============
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dragon_ultra_real_auto:app", host="0.0.0.0", port=8000, reload=False)