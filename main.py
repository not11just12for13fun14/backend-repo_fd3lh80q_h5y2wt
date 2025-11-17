import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from PIL import Image

from database import db, create_document, get_documents
from schemas import User, Scan

# Environment
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-key")
JWT_ALG = "HS256"
FREE_SCANS_DEFAULT = int(os.getenv("FREE_SCANS_DEFAULT", "5"))

# Auth utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterModel(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class ProfileUpdateModel(BaseModel):
    name: Optional[str] = None
    profile_context: Optional[dict] = None


class ScanRequest(BaseModel):
    input_type: str
    text: Optional[str] = None
    image_base64: Optional[str] = None


class ScanResponse(BaseModel):
    risk_level: str
    red_flags: List[str]
    rationale: str
    scans_remaining: int


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(user_id: str, expires_delta: timedelta = timedelta(days=7)) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + expires_delta,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_user_from_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Fetch user from DB
        from bson.objectid import ObjectId
        user_doc = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        return user_doc
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/")
def read_root():
    return {"message": "RedRadar Backend running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# Auth routes
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterModel):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        name=payload.name,
        plan="free",
        scans_used=0,
        free_scans_quota=FREE_SCANS_DEFAULT,
        profile_context={},
        is_active=True,
    )
    user_id = create_document("user", user)
    token = create_access_token(user_id)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token(str(user["_id"]))
    return TokenResponse(access_token=token)


@app.get("/me")
def get_me(current_user=Depends(get_user_from_token)):
    current_user["_id"] = str(current_user["_id"])  # serialize
    return current_user


@app.put("/me")
def update_profile(update: ProfileUpdateModel, current_user=Depends(get_user_from_token)):
    updates = {}
    if update.name is not None:
        updates["name"] = update.name
    if update.profile_context is not None:
        updates["profile_context"] = update.profile_context
    if updates:
        db["user"].update_one({"_id": current_user["_id"]}, {"$set": updates})
    return {"updated": True}


# Simple AI scan stub - replace with real provider call

def call_ai_red_radar(text: Optional[str], image_path: Optional[str], context: dict) -> dict:
    # Heuristic placeholder to simulate AI analysis
    red_flags = []
    rationale_parts = []
    risk = "low"

    if text:
        lower = text.lower()
        if any(k in lower for k in ["transfer", "wire", "crypto", "urgent", "password", "login", "free money", "limited time"]):
            red_flags.append("Language suggests scam or pressure tactics")
        if "click" in lower and "link" in lower:
            red_flags.append("Asks to click a suspicious link")
        if "verify" in lower and ("account" in lower or "identity" in lower):
            red_flags.append("Requests verification outside official channels")
        if any(f in lower for f in ["sss", "xxx", "0000"]):
            red_flags.append("Contains suspicious patterns")
        if len(lower) > 500:
            red_flags.append("Unusually long message for its purpose")
        if any(dom in lower for dom in [".ru", ".biz", "bit.ly", "tinyurl"]):
            red_flags.append("Potentially shady domains detected")

    if image_path:
        red_flags.append("Image content not analyzed in stub")

    # Use context to refine rationale
    if context.get("role") == "finanzas":
        rationale_parts.append("Usuario en finanzas: foco en fraudes financieros")
    if context.get("age") and context["age"] < 21:
        rationale_parts.append("Usuario joven: cuidado con estafas de becas/empleo")

    if len(red_flags) >= 3:
        risk = "high"
    elif len(red_flags) == 2:
        risk = "medium"

    rationale = "; ".join(rationale_parts) or "Análisis basado en patrones comunes de estafa y contexto provisto."

    return {
        "risk_level": risk,
        "red_flags": red_flags or ["No se detectaron banderas rojas evidentes"],
        "rationale": rationale,
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_payload(payload: ScanRequest, current_user=Depends(get_user_from_token)):
    # Check quota
    is_free = current_user.get("plan", "free") == "free"
    scans_used = int(current_user.get("scans_used", 0))
    free_quota = int(current_user.get("free_scans_quota", FREE_SCANS_DEFAULT))
    if is_free and scans_used >= free_quota:
        raise HTTPException(status_code=402, detail="Free scans exhausted. Please subscribe.")

    # Process AI call (stub)
    context = current_user.get("profile_context", {}) or {}
    result = call_ai_red_radar(text=payload.text, image_path=None, context=context)

    # Record scan
    scan_doc = {
        "user_id": str(current_user["_id"]),
        "input_type": payload.input_type,
        "text": payload.text,
        "risk_level": result["risk_level"],
        "red_flags": result["red_flags"],
        "rationale": result["rationale"],
        "created_at": datetime.now(timezone.utc),
    }
    db["scan"].insert_one(scan_doc)

    # Increment usage
    if is_free:
        db["user"].update_one({"_id": current_user["_id"]}, {"$inc": {"scans_used": 1}})
        scans_used += 1

    scans_remaining = (free_quota - scans_used) if is_free else 9999

    return ScanResponse(
        risk_level=result["risk_level"],
        red_flags=result["red_flags"],
        rationale=result["rationale"],
        scans_remaining=max(scans_remaining, 0),
    )


# Image upload variant (optional Form+File)
@app.post("/scan/image", response_model=ScanResponse)
async def scan_image(
    file: UploadFile = File(...),
    text: Optional[str] = Form(None),
    current_user=Depends(get_user_from_token),
):
    is_free = current_user.get("plan", "free") == "free"
    scans_used = int(current_user.get("scans_used", 0))
    free_quota = int(current_user.get("free_scans_quota", FREE_SCANS_DEFAULT))
    if is_free and scans_used >= free_quota:
        raise HTTPException(status_code=402, detail="Free scans exhausted. Please subscribe.")

    # Save temp image
    contents = await file.read()
    tmp_path = f"/tmp/{datetime.now().timestamp()}_{file.filename}"
    with open(tmp_path, "wb") as f:
        f.write(contents)

    context = current_user.get("profile_context", {}) or {}
    result = call_ai_red_radar(text=text, image_path=tmp_path, context=context)

    scan_doc = {
        "user_id": str(current_user["_id"]),
        "input_type": "image",
        "text": text,
        "risk_level": result["risk_level"],
        "red_flags": result["red_flags"],
        "rationale": result["rationale"],
        "created_at": datetime.now(timezone.utc),
    }
    db["scan"].insert_one(scan_doc)

    if is_free:
        db["user"].update_one({"_id": current_user["_id"]}, {"$inc": {"scans_used": 1}})
        scans_used += 1

    scans_remaining = (free_quota - scans_used) if is_free else 9999

    try:
        os.remove(tmp_path)
    except Exception:
        pass

    return ScanResponse(
        risk_level=result["risk_level"],
        red_flags=result["red_flags"],
        rationale=result["rationale"],
        scans_remaining=max(scans_remaining, 0),
    )


# Subscription endpoints (stub)
@app.post("/billing/subscribe")
def subscribe(current_user=Depends(get_user_from_token)):
    db["user"].update_one({"_id": current_user["_id"]}, {"$set": {"plan": "pro"}})
    return {"status": "subscribed"}


@app.post("/billing/cancel")
def cancel(current_user=Depends(get_user_from_token)):
    db["user"].update_one({"_id": current_user["_id"]}, {"$set": {"plan": "free"}})
    return {"status": "canceled"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
