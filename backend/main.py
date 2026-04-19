import os
import pyotp
import jwt
import httpx
import hashlib
import logging
import asyncio

from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# ─── Konfiqurasiya ────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "millisec_super_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://millisec_user:millisec_password@db:5432/millisec_db"
)

SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "http://splunk:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "your-splunk-hec-token")

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("millisec-api")

# ─── Splunk HEC (Düzəldilmiş Arxa Plan Versiyası) ─────────────────────────────
async def _actual_send_to_splunk(event_data: dict):
    payload = {
        "time": datetime.utcnow().timestamp(),
        "host": "millisec-api",
        "source": "millisec-backend",
        "sourcetype": "millisec:api",
        "index": "main",
        "event": event_data
    }
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.post(SPLUNK_HEC_URL, json=payload, headers=headers)
            if resp.status_code != 200:
                logger.warning(f"Splunk HEC xətası: {resp.status_code} - {resp.text}")
    except Exception as e:
        logger.error(f"Splunk-a göndərmə uğursuz: {e}")

async def send_to_splunk(event_data: dict):
    # Asinxron Task yaradırıq ki, API cavab vermək üçün Splunk-ı gözləməsin
    asyncio.create_task(_actual_send_to_splunk(event_data))

# ─── Verilənlər Bazası ────────────────────────────────────────────────────────
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"
    id          = Column(Integer, primary_key=True, index=True)
    username    = Column(String, unique=True)
    password    = Column(String)
    role        = Column(String, default="user")
    mfa_secret  = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()

# ─── Pydantic Modelləri ───────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    password: str

class MFAEnableRequest(BaseModel):
    username: str
    mfa_code: str

# ─── JWT ──────────────────────────────────────────────────────────────────────
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def get_current_user(request: Request, db: Session = Depends(get_db)) -> UserDB:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token tapılmadı")
    try:
        payload  = decode_token(auth.split(" ")[1])
        username = payload.get("sub")
        user     = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="İstifadəçi tapılmadı")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token müddəti bitib")
    except Exception:
        raise HTTPException(status_code=401, detail="Səlahiyyətiniz yoxdur")

# ─── FastAPI ──────────────────────────────────────────────────────────────────
app = FastAPI(title="MilliSec Portal API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── STARTUP: DB cədvəllərini yarat ──────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    logger.info("DB cədvəlləri yoxlanılır/yaradılır...")
    Base.metadata.create_all(bind=engine)
    logger.info("DB hazırdır.")

# ─── Middleware ───────────────────────────────────────────────────────────────
@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    start_time = datetime.utcnow()
    response   = await call_next(request)
    duration   = (datetime.utcnow() - start_time).total_seconds() * 1000

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Server"]                 = "MilliSec-Shield"

    client_ip = request.client.host if request.client else "unknown"
    log_event = {
        "timestamp":       start_time.isoformat() + "Z",
        "event_type":      "api_request",
        "method":          request.method,
        "path":            str(request.url.path),
        "status_code":     response.status_code,
        "client_ip":       client_ip,
        "duration_ms":     round(duration, 2),
        "user_agent":      request.headers.get("User-Agent", "unknown"),
        "is_auth_failure": response.status_code in (401, 403),
    }
    await send_to_splunk(log_event)
    return response

# ─── Qeydiyyat ────────────────────────────────────────────────────────────────
@app.post("/api/register")
async def register(reg_data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == reg_data.username).first():
        await send_to_splunk({
            "event_type": "register_failed",
            "reason":     "username_exists",
            "username":   reg_data.username,
            "client_ip":  request.client.host,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
        })
        raise HTTPException(status_code=400, detail="Bu istifadəçi adı artıq mövcuddur!")

    new_user = UserDB(
        username=reg_data.username,
        password=hash_password(reg_data.password),
        role="user"
    )
    db.add(new_user)
    db.commit()

    await send_to_splunk({
        "event_type": "register_success",
        "username":   reg_data.username,
        "client_ip":  request.client.host,
        "timestamp":  datetime.utcnow().isoformat() + "Z",
    })
    return {"message": "Qeydiyyat uğurla tamamlandı!"}

# ─── MFA Quraşdırma ───────────────────────────────────────────────────────────
@app.get("/api/mfa/setup/{username}")
async def setup_mfa(username: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="İstifadəçi tapılmadı")
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.commit()
    totp   = pyotp.TOTP(user.mfa_secret)
    qr_uri = totp.provisioning_uri(name=f"{username}@millisec.net", issuer_name="MilliSec Portal")
    return {"secret": user.mfa_secret, "qr_uri": qr_uri}

# ─── MFA Aktivləşdirmə ────────────────────────────────────────────────────────
@app.post("/api/mfa/enable")
async def enable_mfa(data: MFAEnableRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="İstifadəçi tapılmadı")

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(data.mfa_code):
        user.mfa_enabled = True
        db.commit()
        await send_to_splunk({
            "event_type": "mfa_enabled",
            "username":   data.username,
            "client_ip":  request.client.host,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
        })
        return {"message": "MFA uğurla aktivləşdirildi!"}

    await send_to_splunk({
        "event_type": "mfa_enable_failed",
        "username":   data.username,
        "client_ip":  request.client.host,
        "timestamp":  datetime.utcnow().isoformat() + "Z",
    })
    raise HTTPException(status_code=400, detail="Yanlış MFA kodu!")

# ─── Giriş ────────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def login(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host
    user      = db.query(UserDB).filter(UserDB.username == login_data.username).first()

    if not user or user.password != hash_password(login_data.password):
        await send_to_splunk({
            "event_type":  "login_failed",
            "reason":      "invalid_credentials",
            "username":    login_data.username,
            "client_ip":   client_ip,
            "status_code": 401,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        })
        raise HTTPException(status_code=401, detail="Səhv məlumatlar")

    if not user.mfa_enabled:
        return {
            "mfa_required": True,
            "setup_needed": True,
            "message": "Şirkət siyasətinə əsasən MFA aktivləşdirilməlidir!"
        }

    if not login_data.mfa_code:
        return {"mfa_required": True, "setup_needed": False, "message": "MFA kodunu daxil edin"}

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(login_data.mfa_code):
        await send_to_splunk({
            "event_type":  "login_failed",
            "reason":      "invalid_mfa_code",
            "username":    login_data.username,
            "client_ip":   client_ip,
            "status_code": 401,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        })
        raise HTTPException(status_code=401, detail="MFA kodu yanlışdır!")

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    await send_to_splunk({
        "event_type":  "login_success",
        "username":    user.username,
        "role":        user.role,
        "client_ip":   client_ip,
        "status_code": 200,
        "timestamp":   datetime.utcnow().isoformat() + "Z",
    })
    return {"access_token": access_token, "token_type": "bearer"}

# ─── Profil ───────────────────────────────────────────────────────────────────
@app.get("/api/v1/profile")
async def get_profile(current_user: UserDB = Depends(get_current_user)):
    return {
        "id":          current_user.id,
        "username":    current_user.username,
        "email":       f"{current_user.username}@millisec.net",
        "role":        current_user.role,
        "mfa_enabled": current_user.mfa_enabled,
    }

# ─── Bütün İstifadəçilər (yalnız admin) ──────────────────────────────────────
@app.get("/api/v1/users")
async def get_users(
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        await send_to_splunk({
            "event_type":  "unauthorized_access",
            "endpoint":    "/api/v1/users",
            "username":    current_user.username,
            "client_ip":   request.client.host,
            "status_code": 403,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        })
        raise HTTPException(status_code=403, detail="Yalnız adminlər bu məlumatı görə bilər")

    users = db.query(UserDB).all()
    return [
        {
            "id":          u.id,
            "username":    u.username,
            "email":       f"{u.username}@millisec.net",
            "role":        u.role,
            "mfa_enabled": u.mfa_enabled,
        }
        for u in users
    ]
