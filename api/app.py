import os, re, secrets, hashlib, hmac, base64, json, time
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ["DATABASE_URL"]
TOKEN_SECRET = os.environ.get("TOKEN_SECRET") or secrets.token_urlsafe(48)
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "https://afterhouse.onrender.com").split(",")

app = FastAPI(title="AFTERHOURS API", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in ALLOWED_ORIGINS], allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["Content-Type","Authorization"])

def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)

@app.on_event("startup")
def init_db():
    with db() as conn:
        conn.execute("""
          CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name VARCHAR(40) NOT NULL,
            birth_date DATE NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
          )
        """)
        conn.execute("""
          CREATE TABLE IF NOT EXISTS user_profiles (
            user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            profile_data JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          )
        """)

class Signup(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=2, max_length=40)
    birth_date: str

class Login(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(salt).decode() + "." + base64.urlsafe_b64encode(digest).decode()

def verify_password(password, stored):
    try:
        s, d = stored.split(".")
        salt = base64.urlsafe_b64decode(s.encode())
        expected = base64.urlsafe_b64decode(d.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def make_token(user_id):
    payload = base64.urlsafe_b64encode(json.dumps({"sub": user_id, "exp": int(time.time()) + 86400}).encode()).decode().rstrip("=")
    sig = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    return payload + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

def read_token(token):
    try:
        payload, signature = token.split(".")
        expected = base64.urlsafe_b64encode(hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected): raise ValueError()
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if data["exp"] < int(time.time()): raise ValueError()
        return int(data["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Session invalide ou expirée")

@app.get("/health")
def health():
    return {"status":"ok","service":"AFTERHOURS API"}

@app.post("/auth/signup")
def signup(body: Signup):
    import datetime
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", body.birth_date):
        raise HTTPException(400, "Date de naissance invalide")
    try:
        birth = datetime.date.fromisoformat(body.birth_date)
    except ValueError:
        raise HTTPException(400, "Date de naissance invalide")
    today = datetime.date.today()
    if birth > today:
        raise HTTPException(400, "La date de naissance ne peut pas être dans le futur")
    age = today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    if age < 18 or age > 120:
        raise HTTPException(400, "AFTERHOURS est réservé aux personnes majeures (18+)")
    display_name = body.display_name.strip()
    if len(display_name) < 2:
        raise HTTPException(400, "Le pseudo doit contenir au moins 2 caractères")
    email = body.email.lower().strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Adresse email invalide")
    try:
        with db() as conn:
            row = conn.execute("INSERT INTO users(email,password_hash,display_name,birth_date) VALUES (%s,%s,%s,%s) RETURNING id,email,display_name,birth_date,created_at", (email, hash_password(body.password), display_name, birth)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Cette adresse email possède déjà un compte")
    return {"token":make_token(row["id"]), "user":{"id":row["id"],"email":row["email"],"display_name":row["display_name"],"birth_date":str(row["birth_date"])}}

@app.post("/auth/login")
def login(body: Login):
    with db() as conn:
        row = conn.execute("SELECT id,email,password_hash,display_name,birth_date FROM users WHERE email=%s", (body.email.lower().strip(),)).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Email ou mot de passe incorrect")
    return {"token":make_token(row["id"]), "user":{"id":row["id"],"email":row["email"],"display_name":row["display_name"],"birth_date":str(row["birth_date"])}}


class ProfilePayload(BaseModel):
    profile: dict = Field(default_factory=dict)

@app.get("/profile")
def get_profile(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Connexion requise")
    user_id = read_token(authorization[7:])
    with db() as conn:
        row = conn.execute("SELECT profile_data, updated_at FROM user_profiles WHERE user_id=%s", (user_id,)).fetchone()
    if not row:
        return {"profile": {}, "updated_at": None}
    return {"profile": row["profile_data"], "updated_at": row["updated_at"].isoformat()}

@app.post("/profile")
def save_profile(body: ProfilePayload, authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Connexion requise")
    user_id = read_token(authorization[7:])
    data = body.profile
    if len(json.dumps(data, ensure_ascii=False)) > 50000:
        raise HTTPException(413, "Le profil est trop volumineux")
    allowed_types = {"individual", "couple"}
    if data.get("account_type") not in (None, *allowed_types):
        raise HTTPException(400, "Type de compte invalide")
    for field in ("age_min", "age_max", "distance", "height"):
        if data.get(field) not in (None, ""):
            try:
                value = int(data[field])
            except (TypeError, ValueError):
                raise HTTPException(400, "Valeur numérique invalide")
            bounds = {"age_min": (18, 99), "age_max": (18, 99), "distance": (1, 1000), "height": (100, 250)}[field]
            if not bounds[0] <= value <= bounds[1]:
                raise HTTPException(400, "Valeur hors limites")
    if data.get("age_min") and data.get("age_max") and int(data["age_min"]) > int(data["age_max"]):
        raise HTTPException(400, "L'âge minimum ne peut pas dépasser l'âge maximum")
    with db() as conn:
        conn.execute("""
          INSERT INTO user_profiles(user_id, profile_data, updated_at)
          VALUES (%s, %s::jsonb, now())
          ON CONFLICT (user_id) DO UPDATE
          SET profile_data=EXCLUDED.profile_data, updated_at=now()
        """, (user_id, json.dumps(data, ensure_ascii=False)))
    return {"status": "ok", "profile": data}

@app.get("/me")
def me(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Connexion requise")
    user_id = read_token(authorization[7:])
    with db() as conn:
        row = conn.execute("SELECT id,email,display_name,birth_date,created_at FROM users WHERE id=%s", (user_id,)).fetchone()
    if not row: raise HTTPException(401, "Compte introuvable")
    return {"user":{**row, "birth_date":str(row["birth_date"]), "created_at":row["created_at"].isoformat()}}
