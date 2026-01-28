# OWASP Top 10 Security Reference

This reference provides detailed guidance for each OWASP Top 10 vulnerability category.

---

## A01:2021 - Broken Access Control

Access control enforces policy such that users cannot act outside their intended permissions.

### What to Check

- Missing authorization on API endpoints
- Insecure Direct Object References (IDOR) - accessing other users' data by modifying IDs
- Privilege escalation - regular users accessing admin functions
- CORS misconfiguration allowing unauthorized origins
- Missing function-level access control
- Metadata manipulation (JWT tampering, cookies, hidden fields)
- Force browsing to authenticated pages

### Vulnerable Pattern

```python
# IDOR - No authorization check
@app.get("/api/users/{user_id}/profile")
async def get_profile(user_id: int):
    return await db.get_user(user_id)  # Any user can access any profile
```

### Fixed Pattern

```python
@app.get("/api/users/{user_id}/profile")
async def get_profile(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    return await db.get_user(user_id)
```

### Files to Check

- Route handlers and controllers
- Middleware/authentication layers
- Database queries with user-supplied IDs
- File access operations

---

## A02:2021 - Cryptographic Failures

Failures related to cryptography which often lead to sensitive data exposure.

### What to Check

- Data transmitted in clear text (HTTP, FTP, SMTP)
- Weak or deprecated cryptographic algorithms (MD5, SHA1, DES)
- Default or weak cryptographic keys
- Missing encryption for sensitive data at rest
- Improper certificate validation
- Weak password hashing (plain MD5/SHA without salt)
- Predictable random number generation for security purposes

### Vulnerable Pattern

```python
import hashlib

# Weak password hashing
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# Predictable random
import random
token = random.randint(100000, 999999)  # Predictable!
```

### Fixed Pattern

```python
from passlib.hash import bcrypt
import secrets

# Strong password hashing
def hash_password(password: str) -> str:
    return bcrypt.hash(password)

# Cryptographically secure random
token = secrets.token_urlsafe(32)
```

### Files to Check

- Authentication modules
- Password handling code
- Token generation
- Encryption/decryption utilities
- TLS/SSL configuration

---

## A03:2021 - Injection

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.

### Types

- **SQL Injection** - Manipulating database queries
- **Command Injection** - Executing system commands
- **LDAP Injection** - Manipulating directory queries
- **XPath Injection** - Manipulating XML queries
- **NoSQL Injection** - Manipulating document database queries
- **XXE** - XML External Entity injection

### SQL Injection

```python
# Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Fixed - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Command Injection

```python
# Vulnerable
os.system(f"ping {user_input}")

# Fixed - Use subprocess with list args, validate input
import shlex
import subprocess

if not re.match(r'^[\w.-]+$', user_input):
    raise ValueError("Invalid hostname")
subprocess.run(["ping", "-c", "1", user_input], capture_output=True)
```

### NoSQL Injection

```javascript
// Vulnerable - MongoDB
db.users.find({ username: req.body.username, password: req.body.password })
// Attacker: { "username": "admin", "password": { "$ne": "" } }

// Fixed - Type validation
const username = String(req.body.username);
const password = String(req.body.password);
db.users.find({ username, password })
```

### Files to Check

- Database query builders
- ORM usage (raw queries)
- System command execution
- XML/LDAP processing

---

## A04:2021 - Insecure Design

Insecure design is a broad category representing design and architectural flaws.

### What to Check

- Missing threat modeling
- Lack of rate limiting on sensitive operations
- Missing account lockout mechanisms
- Business logic flaws (race conditions, TOCTOU)
- Insufficient input validation at design level
- Missing security controls in user stories

### Race Condition Example

```python
# Vulnerable - Race condition in balance check
async def transfer(from_id: int, to_id: int, amount: float):
    balance = await get_balance(from_id)
    if balance >= amount:  # Check
        await deduct_balance(from_id, amount)  # Use - race window!
        await add_balance(to_id, amount)

# Fixed - Use database transaction with locking
async def transfer(from_id: int, to_id: int, amount: float):
    async with db.transaction():
        balance = await get_balance_for_update(from_id)  # SELECT FOR UPDATE
        if balance >= amount:
            await deduct_balance(from_id, amount)
            await add_balance(to_id, amount)
```

### Files to Check

- Financial/transaction logic
- Inventory management
- Concurrent operations
- Multi-step workflows

---

## A05:2021 - Security Misconfiguration

Missing or incorrect security hardening across the application stack.

### What to Check

- Default credentials in use
- Unnecessary features enabled (debug mode, directory listing)
- Missing security headers
- Overly permissive CORS
- Verbose error messages exposing stack traces
- Outdated software with known vulnerabilities
- Cloud storage permissions (S3 buckets, etc.)

### Security Headers

```python
# Required headers
headers = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}
```

### CORS Configuration

```python
# Vulnerable - Overly permissive
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  # Dangerous with wildcard!
)

# Fixed - Explicit origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
```

### Files to Check

- Server configuration files
- Framework settings
- Cloud infrastructure configs
- Docker/container configs
- Environment files

---

## A06:2021 - Vulnerable and Outdated Components

Using components with known vulnerabilities.

### What to Check

- Outdated dependencies with known CVEs
- Unmaintained libraries
- Components with security advisories
- Transitive dependencies (dependencies of dependencies)

### Commands to Run

```bash
# Python
pip install safety
safety check -r requirements.txt

# Node.js
npm audit
npm audit --json

# General
snyk test
```

### Files to Check

- `requirements.txt`, `Pipfile`, `pyproject.toml`
- `package.json`, `package-lock.json`
- Docker base images
- System packages

---

## A07:2021 - Identification and Authentication Failures

Confirmation of user identity and session management weaknesses.

### What to Check

- Weak password requirements
- Credential stuffing vulnerabilities (no rate limiting)
- Missing multi-factor authentication for sensitive operations
- Session fixation
- Session IDs in URLs
- Sessions not invalidated on logout
- Missing session timeout
- Passwords stored in plain text or weak hashes

### Session Management

```python
# Vulnerable - Session fixation
@app.post("/login")
async def login(request: Request, credentials: Credentials):
    if verify_credentials(credentials):
        # Using existing session ID - fixation vulnerability!
        request.session["user"] = credentials.username

# Fixed - Regenerate session on login
@app.post("/login")
async def login(request: Request, credentials: Credentials):
    if verify_credentials(credentials):
        request.session.clear()  # Invalidate old session
        request.session.regenerate()  # New session ID
        request.session["user"] = credentials.username
```

### JWT Security

```python
# Vulnerable - No expiration, weak secret
token = jwt.encode({"user_id": user_id}, "secret", algorithm="HS256")

# Fixed - Proper JWT with expiration
token = jwt.encode(
    {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4())  # Unique token ID for revocation
    },
    os.environ["JWT_SECRET"],  # Strong secret from env
    algorithm="HS256"
)
```

### Files to Check

- Login/logout handlers
- Password reset flows
- Session management code
- JWT creation/validation
- OAuth implementations

---

## A08:2021 - Software and Data Integrity Failures

Code and infrastructure that does not protect against integrity violations.

### What to Check

- Insecure deserialization
- Untrusted CI/CD pipeline
- Auto-update without signature verification
- Insecure use of pickle, yaml.load, eval
- Missing integrity checks on downloads

### Deserialization

```python
# Vulnerable - Pickle can execute arbitrary code
import pickle
data = pickle.loads(user_input)  # RCE!

# Vulnerable - yaml.load with untrusted input
import yaml
data = yaml.load(user_input)  # Code execution possible

# Fixed - Use safe alternatives
import json
data = json.loads(user_input)  # Safe

import yaml
data = yaml.safe_load(user_input)  # Safe
```

### Files to Check

- Data serialization code
- File upload handlers
- CI/CD configurations
- Package management scripts

---

## A09:2021 - Security Logging and Monitoring Failures

Without logging and monitoring, breaches cannot be detected.

### What to Check

- Login/logout not logged
- Failed login attempts not logged
- High-value transactions not logged
- Logs not protected from tampering
- No alerting for suspicious activity
- Sensitive data in logs (passwords, tokens, PII)

### What to Log

```python
# Security events to log
logger.info(f"Login successful: user={username}, ip={request.client.host}")
logger.warning(f"Login failed: user={username}, ip={request.client.host}, reason={reason}")
logger.warning(f"Access denied: user={current_user.id}, resource={resource}, ip={request.client.host}")
logger.info(f"Password changed: user={user_id}")
logger.warning(f"Rate limit exceeded: ip={request.client.host}, endpoint={endpoint}")
```

### What NOT to Log

```python
# Never log these
logger.info(f"Login: user={username}, password={password}")  # NO!
logger.info(f"Token: {jwt_token}")  # NO!
logger.info(f"Credit card: {card_number}")  # NO!
```

### Files to Check

- Logging configuration
- Authentication handlers
- Error handlers
- Transaction processing

---

## A10:2021 - Server-Side Request Forgery (SSRF)

SSRF flaws occur when an application fetches a remote resource without validating the user-supplied URL.

### What to Check

- URL fetching based on user input
- Webhook implementations
- File imports from URLs
- PDF generators fetching resources
- Image processing from URLs

### Vulnerable Pattern

```python
# Vulnerable - Fetches any URL
@app.post("/fetch")
async def fetch_url(url: str):
    response = requests.get(url)  # Can access internal services!
    return response.text

# Attacker request: url=http://169.254.169.254/latest/meta-data/
# Attacker request: url=http://localhost:6379/
```

### Fixed Pattern

```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = ["api.example.com", "cdn.example.com"]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)

    # Only allow HTTPS
    if parsed.scheme != "https":
        return False

    # Check against allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        return False

    # Block private IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return False
    except ValueError:
        pass  # Not an IP, hostname already checked

    return True

@app.post("/fetch")
async def fetch_url(url: str):
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL not allowed")
    response = requests.get(url)
    return response.text
```

### Files to Check

- HTTP client usage
- Webhook handlers
- File/image import features
- API integrations
