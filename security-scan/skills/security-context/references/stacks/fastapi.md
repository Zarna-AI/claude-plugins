# FastAPI Security Reference

Security patterns and common vulnerabilities specific to FastAPI and Python web applications.

---

## Authentication & Authorization

### JWT Implementation

```python
# Vulnerable - No expiration, weak validation
@app.get("/protected")
async def protected(token: str = Header()):
    payload = jwt.decode(token, "secret", algorithms=["HS256"])
    return {"user": payload["user"]}

# Fixed - Proper JWT validation
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET,
            algorithms=["HS256"]
        )

        # Check expiration
        if datetime.fromtimestamp(payload["exp"]) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Token expired")

        user = await get_user(payload["sub"])
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### Dependency Injection for Auth

```python
# Always use dependency injection for auth checks
async def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return current_user

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, admin: User = Depends(require_admin)):
    # Only admins can reach this
    pass
```

---

## Input Validation with Pydantic

### Strict Type Validation

```python
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr  # Validates email format
    password: str = Field(..., min_length=8, max_length=128)
    age: int = Field(..., ge=0, le=150)

    @validator("password")
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain uppercase")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain digit")
        return v

# Vulnerable - No validation
@app.post("/users")
async def create_user(data: dict):  # Accepts anything!
    pass

# Fixed - Pydantic validation
@app.post("/users")
async def create_user(user: UserCreate):  # Validated!
    pass
```

### Path Parameter Validation

```python
from fastapi import Path

# Vulnerable - No validation on path param
@app.get("/files/{file_path:path}")
async def get_file(file_path: str):
    return FileResponse(f"/data/{file_path}")  # Path traversal!

# Fixed - Validate and sanitize
import os

@app.get("/files/{file_id}")
async def get_file(file_id: int = Path(..., gt=0)):
    file_record = await db.get_file(file_id)
    if not file_record:
        raise HTTPException(status_code=404)

    # Resolve and validate path
    base_path = os.path.realpath("/data/files")
    full_path = os.path.realpath(os.path.join(base_path, file_record.filename))

    if not full_path.startswith(base_path):
        raise HTTPException(status_code=400, detail="Invalid path")

    return FileResponse(full_path)
```

---

## SQL Injection Prevention

### Using SQLAlchemy Safely

```python
# Vulnerable - String formatting
async def search_users(query: str):
    result = await db.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    return result.fetchall()

# Fixed - Parameterized queries
from sqlalchemy import text

async def search_users(query: str):
    result = await db.execute(
        text("SELECT * FROM users WHERE name LIKE :query"),
        {"query": f"%{query}%"}
    )
    return result.fetchall()

# Best - Use ORM methods
async def search_users(query: str):
    return await db.query(User).filter(User.name.ilike(f"%{query}%")).all()
```

---

## Async Security Considerations

### Race Conditions

```python
# Vulnerable - Race condition in async code
@app.post("/transfer")
async def transfer(from_id: int, to_id: int, amount: float):
    from_balance = await get_balance(from_id)

    if from_balance >= amount:
        # Another request could modify balance here!
        await update_balance(from_id, from_balance - amount)
        await update_balance(to_id, (await get_balance(to_id)) + amount)

# Fixed - Use database transaction with locking
@app.post("/transfer")
async def transfer(from_id: int, to_id: int, amount: float):
    async with database.transaction():
        # SELECT FOR UPDATE locks the row
        from_account = await db.execute(
            text("SELECT balance FROM accounts WHERE id = :id FOR UPDATE"),
            {"id": from_id}
        ).fetchone()

        if from_account.balance >= amount:
            await db.execute(
                text("UPDATE accounts SET balance = balance - :amount WHERE id = :id"),
                {"amount": amount, "id": from_id}
            )
            await db.execute(
                text("UPDATE accounts SET balance = balance + :amount WHERE id = :id"),
                {"amount": amount, "id": to_id}
            )
```

---

## File Upload Security

```python
import magic
from pathlib import Path
import uuid

ALLOWED_TYPES = {"image/jpeg", "image/png", "application/pdf"}
MAX_SIZE = 10 * 1024 * 1024  # 10MB

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # Check file size
    contents = await file.read()
    if len(contents) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="File too large")

    # Check MIME type (not just extension!)
    mime_type = magic.from_buffer(contents, mime=True)
    if mime_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="File type not allowed")

    # Generate safe filename
    ext = Path(file.filename).suffix.lower()
    if ext not in {".jpg", ".jpeg", ".png", ".pdf"}:
        raise HTTPException(status_code=400, detail="Invalid extension")

    safe_filename = f"{uuid.uuid4()}{ext}"

    # Store outside web root
    upload_path = Path("/data/uploads") / safe_filename
    upload_path.write_bytes(contents)

    return {"filename": safe_filename}
```

---

## Command Injection

```python
import subprocess
import shlex

# Vulnerable
@app.get("/ping")
async def ping(host: str):
    result = os.popen(f"ping -c 1 {host}").read()  # Command injection!
    return {"result": result}

# Fixed - Use subprocess with list args and validation
import re

@app.get("/ping")
async def ping(host: str):
    # Validate hostname format
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname")

    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5
    )
    return {"result": result.stdout}
```

---

## Environment & Configuration

### Secrets Management

```python
# Vulnerable - Hardcoded secrets
DATABASE_URL = "postgresql://user:password123@localhost/db"
JWT_SECRET = "mysecretkey"

# Fixed - Environment variables
from pydantic import BaseSettings

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str

    class Config:
        env_file = ".env"

settings = Settings()

# .env file (never commit!)
# DATABASE_URL=postgresql://...
# JWT_SECRET=<generated-secret>
```

### Debug Mode

```python
# Vulnerable - Debug in production
app = FastAPI(debug=True)  # Exposes stack traces!

# Fixed - Environment-based
import os

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
app = FastAPI(debug=DEBUG)

# Also check for other debug settings
if not DEBUG:
    # Disable docs in production if needed
    app = FastAPI(docs_url=None, redoc_url=None)
```

---

## Error Handling

```python
# Vulnerable - Exposes internal details
@app.exception_handler(Exception)
async def exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "traceback": traceback.format_exc()}
    )

# Fixed - Generic error messages
@app.exception_handler(Exception)
async def exception_handler(request, exc):
    # Log the full error internally
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    # Return generic message to user
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred"}
    )
```

---

## Security Headers Middleware

```python
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response

app.add_middleware(SecurityHeadersMiddleware)
```

---

## Rate Limiting

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginRequest):
    pass

@app.post("/api/expensive-operation")
@limiter.limit("10/hour")
async def expensive_operation(request: Request):
    pass
```

---

## Files to Check in FastAPI Projects

| File/Pattern | What to Look For |
|--------------|------------------|
| `main.py`, `app.py` | Debug mode, middleware, CORS |
| `routers/*.py` | Auth dependencies, input validation |
| `models/*.py` | Pydantic validators, field constraints |
| `db/*.py` | Raw SQL queries, ORM misuse |
| `auth/*.py` | JWT handling, password hashing |
| `config.py`, `settings.py` | Hardcoded secrets, debug flags |
| `.env` | Should not be in git! |
| `requirements.txt` | Outdated packages |
