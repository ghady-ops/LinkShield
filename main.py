from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import sqlite3, random, smtplib, os
import bcrypt
from email.mime.text import MIMEText
from datetime import datetime, timedelta
app = FastAPI(title="LinkShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from dotenv import load_dotenv
import os

load_dotenv()

GMAIL_USER     = os.getenv("EMAIL_USER")
GMAIL_PASSWORD = os.getenv("EMAIL_PASS")
MODEL_PATH     = os.getenv("MODEL_PATH", "FVJER/linkshield-model")

from huggingface_hub import login
HF_TOKEN = os.getenv("HF_TOKEN")
if HF_TOKEN:
    login(token=HF_TOKEN)

# ── Database ────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("linkshield.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            email    TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS otps (
            email   TEXT PRIMARY KEY,
            code    TEXT NOT NULL,
            expires TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT NOT NULL,
            url        TEXT NOT NULL,
            risk       TEXT NOT NULL,
            label      TEXT NOT NULL,
            confidence REAL NOT NULL,
            scanned_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ── Load model ───────────────────────────────────────────────
print("Loading model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model     = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()
print("Model loaded ✅")

# ── Helpers ──────────────────────────────────────────────────
def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_password(pw: str, hashed) -> bool:
    if isinstance(hashed, str):
        hashed = hashed.encode()
    return bcrypt.checkpw(pw.encode(), hashed)

def send_otp_email(to_email: str, code: str):
    msg = MIMEText(f"""
مرحباً 👋

رمز التحقق الخاص بك في LinkShield هو:

🔐  {code}

الرمز صالح لمدة 10 دقائق.

— فريق LinkShield
""", "plain", "utf-8")
    msg["Subject"] = "رمز التحقق - LinkShield"
    msg["From"]    = GMAIL_USER
    msg["To"]      = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(GMAIL_USER, GMAIL_PASSWORD)
        smtp.send_message(msg)

def generate_otp(email: str) -> str:
    code    = str(random.randint(1000, 9999))
    expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    conn    = get_db()
    conn.execute("INSERT OR REPLACE INTO otps (email, code, expires) VALUES (?,?,?)",
                 (email, code, expires))
    conn.commit()
    conn.close()
    return code

def verify_otp_code(email: str, code: str) -> bool:
    conn = get_db()
    row  = conn.execute("SELECT code, expires FROM otps WHERE email=?", (email,)).fetchone()
    conn.close()
    if not row:
        return False
    if datetime.utcnow() > datetime.fromisoformat(row["expires"]):
        return False
    return row["code"] == code

# ── Schemas ──────────────────────────────────────────────────
class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class OTPRequest(BaseModel):
    email: str

class OTPVerify(BaseModel):
    email: str
    code: str

class ResetPassword(BaseModel):
    email: str
    code: str
    new_password: str

class ScanRequest(BaseModel):
    url: str
    email: str = ""

# ── Auth Endpoints ───────────────────────────────────────────
@app.post("/signup")
def signup(req: SignupRequest):
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (name, email, password) VALUES (?,?,?)",
                     (req.name.strip(), req.email.strip().lower(), hash_password(req.password)))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "البريد الإلكتروني مسجل مسبقاً")
    finally:
        conn.close()

    code = generate_otp(req.email.strip().lower())
    try:
        send_otp_email(req.email.strip(), code)
    except Exception as e:
        raise HTTPException(500, f"تعذّر إرسال OTP: {e}")

    return {"message": "تم إنشاء الحساب، تحقق من بريدك للرمز"}

@app.post("/login")
def login(req: LoginRequest):
    conn  = get_db()
    email = req.email.strip().lower()
    user  = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not check_password(req.password, user["password"]):
        raise HTTPException(401, "البريد أو كلمة المرور غير صحيحة")
    return {"message": "تم تسجيل الدخول", "name": user["name"], "email": user["email"]}

@app.post("/send-otp")
def send_otp(req: OTPRequest):
    email = req.email.strip().lower()
    code  = generate_otp(email)
    try:
        send_otp_email(email, code)
    except Exception as e:
        raise HTTPException(500, f"تعذّر إرسال OTP: {e}")
    return {"message": "تم إرسال الرمز"}

@app.post("/verify-otp")
def verify_otp(req: OTPVerify):
    if not verify_otp_code(req.email.strip().lower(), req.code.strip()):
        raise HTTPException(400, "الرمز غير صحيح أو منتهي الصلاحية")
    return {"message": "تم التحقق بنجاح"}

@app.post("/reset-password")
def reset_password(req: ResetPassword):
    email = req.email.strip().lower()
    if not verify_otp_code(email, req.code.strip()):
        raise HTTPException(400, "الرمز غير صحيح أو منتهي الصلاحية")
    conn = get_db()
    conn.execute("UPDATE users SET password=? WHERE email=?",
                 (hash_password(req.new_password), email))
    conn.execute("DELETE FROM otps WHERE email=?", (email,))
    conn.commit()
    conn.close()
    return {"message": "تم تغيير كلمة المرور"}

# ── Scan Endpoint ────────────────────────────────────────────
@app.post("/scan")
def scan(req: ScanRequest):
    url    = req.url.strip()
    inputs = tokenizer(url, return_tensors="pt", truncation=True, max_length=128, padding=True)
    with torch.no_grad():
        logits = model(**inputs).logits
    probs      = torch.softmax(logits, dim=-1)[0]
    pred_id    = int(torch.argmax(probs))
    confidence = float(probs[pred_id])

    pct = confidence * 100
    if pct < 75:
        risk  = "medium"
        label = "Medium"
    elif pred_id == 1:
        risk  = "high"
        label = "Unsafe"
    else:
        risk  = "low"
        label = "Safe"

    if req.email:
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO scan_history (email, url, risk, label, confidence) VALUES (?,?,?,?,?)",
                (req.email.strip().lower(), url, risk, label, round(confidence, 4))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    return {
        "url":        url,
        "risk":       risk,
        "confidence": round(confidence, 4),
        "label":      label,
    }

@app.get("/history/{email}")
def get_history(email: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT url, risk, label, confidence, scanned_at FROM scan_history WHERE email=? ORDER BY scanned_at DESC LIMIT 50",
        (email.strip().lower(),)
    ).fetchall()
    conn.close()
    return {"history": [dict(r) for r in rows]}

@app.get("/health")
def health():
    return {"status": "ok"}
