# SOC 2 Compliance Reference

SOC 2 (System and Organization Controls 2) focuses on five Trust Service Criteria. This reference helps identify code and configuration issues relevant to SOC 2 compliance.

---

## Trust Service Criteria Overview

| Criteria | Focus | Code Relevance |
|----------|-------|----------------|
| **Security** | Protection against unauthorized access | Auth, encryption, access control |
| **Availability** | System uptime and recovery | Error handling, redundancy |
| **Processing Integrity** | Accurate data processing | Validation, data integrity |
| **Confidentiality** | Data protection | Encryption, access control |
| **Privacy** | Personal information handling | PII handling, consent |

---

## Security (Common Criteria - Required)

### CC6.1 - Logical Access Controls

**What auditors check:**
- How users are authenticated
- How access is authorized
- Session management
- Password policies

**Code review focus:**

```python
# Authentication implementation
# - Strong password requirements
# - MFA support
# - Account lockout after failed attempts
# - Session timeout

# Check for:
PASSWORD_MIN_LENGTH = 8  # Should be 12+
PASSWORD_REQUIRE_SPECIAL = True
MAX_LOGIN_ATTEMPTS = 5
SESSION_TIMEOUT_MINUTES = 30
MFA_ENABLED = True

# Authorization checks on every endpoint
@require_permission("users:read")
def get_users():
    pass
```

**Evidence to collect:**
- Authentication code/configuration
- Password policy settings
- Role-based access control implementation
- Session management code

### CC6.2 - Access Removal

**Code review focus:**

```python
# User deprovisioning
async def deactivate_user(user_id: str):
    # Revoke all active sessions
    await revoke_all_sessions(user_id)

    # Remove API keys
    await delete_api_keys(user_id)

    # Disable account
    await db.users.update(user_id, {"is_active": False})

    # Audit log
    await audit_log("user.deactivated", {"user_id": user_id})
```

### CC6.6 - Security Events

**Code review focus:**

```python
# Logging security events
EVENTS_TO_LOG = [
    "login.success",
    "login.failure",
    "logout",
    "password.changed",
    "permission.denied",
    "data.exported",
    "user.created",
    "user.deleted",
    "role.changed",
]

async def security_event(event_type: str, details: dict):
    await db.audit_logs.insert({
        "event": event_type,
        "timestamp": datetime.utcnow(),
        "user_id": get_current_user_id(),
        "ip_address": get_client_ip(),
        "details": details
    })
```

### CC6.7 - Encryption

**Code review focus:**

```python
# Data at rest encryption
# - Database encryption enabled
# - File storage encryption
# - Backup encryption

# Data in transit
# - TLS 1.2+ required
# - Certificate validation
# - Secure cipher suites

# Check configurations:
FORCE_HTTPS = True
TLS_MIN_VERSION = "1.2"
HSTS_ENABLED = True

# Sensitive data encryption
from cryptography.fernet import Fernet

def encrypt_pii(data: str) -> str:
    f = Fernet(settings.ENCRYPTION_KEY)
    return f.encrypt(data.encode()).decode()
```

---

## Availability

### A1.1 - System Availability

**Code review focus:**

```python
# Error handling that doesn't crash the system
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    # Alert ops team
    await alert_ops("Unhandled exception", str(exc))
    # Return graceful error
    return JSONResponse(
        status_code=500,
        content={"error": "Internal error", "request_id": request.state.request_id}
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    checks = {
        "database": await check_db_connection(),
        "cache": await check_cache_connection(),
        "external_api": await check_external_api(),
    }
    all_healthy = all(checks.values())
    return {"status": "healthy" if all_healthy else "degraded", "checks": checks}
```

### A1.2 - Recovery

**Code review focus:**

```python
# Database transactions with rollback
async def process_order(order_data: dict):
    async with db.transaction() as tx:
        try:
            order = await create_order(order_data)
            await process_payment(order)
            await update_inventory(order)
            await tx.commit()
        except Exception as e:
            await tx.rollback()
            logger.error(f"Order failed, rolled back: {e}")
            raise

# Backup verification
# Check that backup scripts exist and run regularly
```

---

## Processing Integrity

### PI1.1 - Input Validation

**Code review focus:**

```python
# Comprehensive input validation
from pydantic import BaseModel, validator, constr

class OrderCreate(BaseModel):
    product_id: constr(min_length=1, max_length=50)
    quantity: int
    price: Decimal

    @validator("quantity")
    def quantity_positive(cls, v):
        if v <= 0:
            raise ValueError("Quantity must be positive")
        if v > 1000:
            raise ValueError("Quantity exceeds maximum")
        return v

    @validator("price")
    def price_valid(cls, v):
        if v <= 0:
            raise ValueError("Price must be positive")
        return v.quantize(Decimal("0.01"))  # 2 decimal places
```

### PI1.2 - Data Integrity

**Code review focus:**

```python
# Checksums for critical data
import hashlib

def store_document(content: bytes, metadata: dict):
    checksum = hashlib.sha256(content).hexdigest()
    return db.documents.insert({
        "content": content,
        "checksum": checksum,
        "metadata": metadata
    })

def verify_document(doc_id: str) -> bool:
    doc = db.documents.get(doc_id)
    actual_checksum = hashlib.sha256(doc.content).hexdigest()
    return actual_checksum == doc.checksum
```

---

## Confidentiality

### C1.1 - Confidential Information Identification

**Code review focus:**

```python
# Data classification
class DataClassification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

# Access based on classification
def can_access(user: User, resource: Resource) -> bool:
    if resource.classification == DataClassification.RESTRICTED:
        return user.has_permission("restricted:read")
    if resource.classification == DataClassification.CONFIDENTIAL:
        return user.has_permission("confidential:read")
    return True
```

### C1.2 - Confidential Information Disposal

**Code review focus:**

```python
# Secure deletion
async def delete_user_data(user_id: str):
    # Delete from all tables
    await db.user_profiles.delete(user_id=user_id)
    await db.user_documents.delete(user_id=user_id)
    await db.user_activity.delete(user_id=user_id)

    # Delete from file storage
    await storage.delete_folder(f"users/{user_id}")

    # Delete from search index
    await search.delete_by_query({"user_id": user_id})

    # Audit log (keep for compliance)
    await audit_log("user.data_deleted", {"user_id": user_id})
```

---

## Privacy

### P1.1 - Privacy Notice

**Code review focus:**

```python
# Consent tracking
class UserConsent(BaseModel):
    user_id: str
    consent_type: str  # "marketing", "analytics", "data_processing"
    granted: bool
    timestamp: datetime
    ip_address: str
    consent_version: str  # Track which privacy policy version

async def record_consent(user_id: str, consent_type: str, granted: bool):
    await db.consents.insert({
        "user_id": user_id,
        "consent_type": consent_type,
        "granted": granted,
        "timestamp": datetime.utcnow(),
        "ip_address": get_client_ip(),
        "consent_version": CURRENT_PRIVACY_POLICY_VERSION
    })
```

### P3.1 - Personal Information Collection

**Code review focus:**

```python
# Minimal data collection
class UserSignup(BaseModel):
    email: EmailStr  # Required
    name: str  # Required
    # Don't collect unnecessary data
    # phone: Optional[str]  # Only if needed
    # address: Optional[str]  # Only if needed

# Data minimization in queries
async def get_user_for_display(user_id: str):
    # Only select needed fields
    return await db.users.select(
        "id", "name", "avatar_url"
    ).where(id=user_id)

    # NOT: SELECT * FROM users
```

---

## Code Review Checklist for SOC 2

### Security
- [ ] Strong authentication implemented (passwords, MFA)
- [ ] Role-based access control on all endpoints
- [ ] Session management (timeout, invalidation)
- [ ] Encryption at rest and in transit
- [ ] Security event logging
- [ ] Vulnerability scanning in CI/CD

### Availability
- [ ] Error handling doesn't crash system
- [ ] Health check endpoints
- [ ] Database transaction handling
- [ ] Graceful degradation

### Processing Integrity
- [ ] Input validation on all endpoints
- [ ] Data integrity checks (checksums, constraints)
- [ ] Audit trails for data changes

### Confidentiality
- [ ] Data classification implemented
- [ ] Access control based on classification
- [ ] Secure data disposal

### Privacy
- [ ] Consent management
- [ ] Minimal data collection
- [ ] Data subject rights (access, deletion)

---

## Evidence Collection

During security review, note locations of:

1. **Authentication code** - For CC6.1
2. **Authorization middleware** - For CC6.1
3. **Audit logging** - For CC6.6
4. **Encryption configuration** - For CC6.7
5. **Input validation schemas** - For PI1.1
6. **Error handling** - For A1.1
7. **Data deletion routines** - For C1.2
8. **Consent tracking** - For P1.1

Document file paths and line numbers for auditor reference.
