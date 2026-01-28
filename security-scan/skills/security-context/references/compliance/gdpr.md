# GDPR Compliance Reference

General Data Protection Regulation requirements relevant to code and application security.

---

## Key GDPR Principles in Code

| Principle | Code Implication |
|-----------|------------------|
| **Lawfulness** | Document legal basis for processing |
| **Purpose Limitation** | Only use data for stated purposes |
| **Data Minimization** | Collect only necessary data |
| **Accuracy** | Allow users to update data |
| **Storage Limitation** | Implement data retention/deletion |
| **Integrity & Confidentiality** | Security measures |
| **Accountability** | Audit trails, documentation |

---

## Article 5 - Data Processing Principles

### Data Minimization

```python
# WRONG - Collecting unnecessary data
class UserSignup(BaseModel):
    email: str
    password: str
    name: str
    phone: str  # Do you need this?
    address: str  # Do you need this?
    date_of_birth: date  # Do you need this?
    gender: str  # Do you need this?

# RIGHT - Minimal collection
class UserSignup(BaseModel):
    email: str
    password: str
    # Only collect what's necessary for the service

# In queries - select only needed fields
async def get_users_for_export():
    # WRONG
    return await db.query("SELECT * FROM users")

    # RIGHT
    return await db.query("SELECT id, email FROM users")
```

### Purpose Limitation

```python
# Track purpose of data collection
class DataUsagePurpose(Enum):
    SERVICE_DELIVERY = "service_delivery"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    LEGAL_COMPLIANCE = "legal_compliance"

# Check purpose before using data
async def send_marketing_email(user_id: str):
    consent = await get_consent(user_id, DataUsagePurpose.MARKETING)
    if not consent or not consent.granted:
        raise PermissionError("No marketing consent")

    # Proceed with marketing
```

---

## Article 6 - Lawful Basis

### Consent Management

```python
from datetime import datetime
from enum import Enum

class ConsentType(Enum):
    NECESSARY = "necessary"  # No consent needed
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    THIRD_PARTY = "third_party"

class Consent(BaseModel):
    user_id: str
    consent_type: ConsentType
    granted: bool
    timestamp: datetime
    method: str  # "checkbox", "banner", "settings"
    privacy_policy_version: str

# Record consent with full audit trail
async def record_consent(
    user_id: str,
    consent_type: ConsentType,
    granted: bool,
    method: str
):
    await db.consents.insert({
        "user_id": user_id,
        "consent_type": consent_type.value,
        "granted": granted,
        "timestamp": datetime.utcnow(),
        "method": method,
        "privacy_policy_version": CURRENT_PP_VERSION,
        "ip_address": get_client_ip(),
        "user_agent": get_user_agent()
    })

# Check consent before processing
async def track_analytics(user_id: str, event: dict):
    if not await has_consent(user_id, ConsentType.ANALYTICS):
        return  # Don't track without consent

    await analytics.track(user_id, event)
```

### Consent Withdrawal

```python
# Users must be able to withdraw consent easily
@app.post("/api/consent/withdraw")
async def withdraw_consent(
    consent_type: ConsentType,
    user: User = Depends(get_current_user)
):
    await record_consent(
        user_id=user.id,
        consent_type=consent_type,
        granted=False,
        method="user_settings"
    )

    # Stop processing immediately
    if consent_type == ConsentType.MARKETING:
        await unsubscribe_from_marketing(user.id)

    return {"status": "consent_withdrawn"}
```

---

## Article 15 - Right of Access

### Data Export

```python
@app.get("/api/my-data")
async def export_user_data(user: User = Depends(get_current_user)):
    """
    GDPR Article 15 - Right of access
    User can request all their personal data
    """
    data = {
        "profile": await get_user_profile(user.id),
        "activity": await get_user_activity(user.id),
        "documents": await get_user_documents(user.id),
        "consents": await get_user_consents(user.id),
        "communications": await get_user_communications(user.id),
    }

    # Log the access request
    await audit_log("gdpr.data_access", {"user_id": user.id})

    return data

# Provide in machine-readable format
@app.get("/api/my-data/download")
async def download_user_data(user: User = Depends(get_current_user)):
    data = await export_user_data(user)
    return Response(
        content=json.dumps(data, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=my_data_{user.id}.json"
        }
    )
```

---

## Article 16 - Right to Rectification

```python
@app.put("/api/profile")
async def update_profile(
    updates: ProfileUpdate,
    user: User = Depends(get_current_user)
):
    """
    GDPR Article 16 - Right to rectification
    Users can correct inaccurate data
    """
    # Log what was changed
    old_data = await get_user_profile(user.id)

    await db.profiles.update(
        {"user_id": user.id},
        updates.dict(exclude_unset=True)
    )

    await audit_log("gdpr.data_rectification", {
        "user_id": user.id,
        "fields_updated": list(updates.dict(exclude_unset=True).keys())
    })

    return {"status": "updated"}
```

---

## Article 17 - Right to Erasure (Right to be Forgotten)

### Complete Data Deletion

```python
@app.delete("/api/account")
async def delete_account(
    confirmation: str,
    user: User = Depends(get_current_user)
):
    """
    GDPR Article 17 - Right to erasure
    Complete deletion of all user data
    """
    if confirmation != "DELETE_MY_ACCOUNT":
        raise HTTPException(400, "Please confirm deletion")

    # Delete from all data stores
    await delete_user_data(user.id)

    return {"status": "account_deleted"}

async def delete_user_data(user_id: str):
    """Delete all personal data for a user"""

    # Primary database
    await db.users.delete(user_id=user_id)
    await db.profiles.delete(user_id=user_id)
    await db.activity.delete(user_id=user_id)

    # File storage
    await storage.delete_folder(f"users/{user_id}")

    # Search indices
    await search.delete_user_documents(user_id)

    # Analytics (anonymize, don't delete for aggregate stats)
    await analytics.anonymize_user(user_id)

    # Third-party services
    await email_service.delete_contact(user_id)
    await crm.delete_contact(user_id)

    # Cache
    await cache.delete_pattern(f"user:{user_id}:*")

    # Audit log (keep for legal compliance, but anonymize)
    await audit_log("gdpr.erasure_completed", {
        "anonymized_id": hash_user_id(user_id),
        "timestamp": datetime.utcnow()
    })
```

### Erasure Exceptions

```python
# Some data may need to be retained for legal reasons
async def delete_user_data(user_id: str):
    # Check for legal holds
    if await has_legal_hold(user_id):
        raise HTTPException(
            400,
            "Cannot delete due to legal hold. Contact support."
        )

    # Financial records may need 7-year retention
    financial_records = await get_financial_records(user_id)
    if financial_records:
        # Anonymize instead of delete
        await anonymize_financial_records(user_id)

    # Delete everything else
    await delete_non_retained_data(user_id)
```

---

## Article 20 - Right to Data Portability

```python
@app.get("/api/my-data/portable")
async def export_portable_data(user: User = Depends(get_current_user)):
    """
    GDPR Article 20 - Right to data portability
    Provide data in structured, machine-readable format
    """
    data = {
        "export_date": datetime.utcnow().isoformat(),
        "format_version": "1.0",
        "user": {
            "email": user.email,
            "name": user.name,
            "created_at": user.created_at.isoformat(),
        },
        "content": await get_user_content(user.id),
        "activity": await get_user_activity(user.id),
    }

    # Standard format (JSON or CSV)
    return Response(
        content=json.dumps(data, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=data_export.json"
        }
    )
```

---

## Article 25 - Privacy by Design

### Default Privacy Settings

```python
# New users should have privacy-friendly defaults
DEFAULT_USER_SETTINGS = {
    "profile_visibility": "private",  # Not public
    "show_in_search": False,
    "marketing_emails": False,  # Opt-in, not opt-out
    "analytics_tracking": False,  # Opt-in
    "third_party_sharing": False,
}

async def create_user(user_data: UserCreate):
    user = await db.users.insert({
        **user_data.dict(),
        "settings": DEFAULT_USER_SETTINGS
    })
    return user
```

### Pseudonymization

```python
import hashlib
import secrets

def pseudonymize_user_id(user_id: str) -> str:
    """Create a pseudonymous identifier"""
    salt = settings.PSEUDONYMIZATION_SALT
    return hashlib.sha256(f"{salt}{user_id}".encode()).hexdigest()[:16]

# Use in analytics
async def track_event(user_id: str, event: str):
    pseudo_id = pseudonymize_user_id(user_id)
    await analytics.track(pseudo_id, event)
    # Original user_id is not stored in analytics
```

---

## Article 32 - Security of Processing

### Encryption

```python
from cryptography.fernet import Fernet

# Encrypt PII at rest
def encrypt_pii(data: str) -> str:
    f = Fernet(settings.ENCRYPTION_KEY)
    return f.encrypt(data.encode()).decode()

def decrypt_pii(encrypted: str) -> str:
    f = Fernet(settings.ENCRYPTION_KEY)
    return f.decrypt(encrypted.encode()).decode()

# Store encrypted
await db.users.insert({
    "email": email,  # May need for lookups
    "phone_encrypted": encrypt_pii(phone),
    "address_encrypted": encrypt_pii(address),
})
```

### Access Controls

```python
# Log all access to personal data
async def get_user_pii(user_id: str, requester: User):
    # Check authorization
    if requester.id != user_id and not requester.is_admin:
        raise HTTPException(403, "Access denied")

    # Log the access
    await audit_log("pii.accessed", {
        "target_user": user_id,
        "requester": requester.id,
        "requester_role": requester.role
    })

    return await db.users.get(user_id)
```

---

## Article 33 - Breach Notification

### Breach Detection & Response

```python
async def detect_potential_breach(event: SecurityEvent):
    """Monitor for potential data breaches"""

    breach_indicators = [
        "bulk_data_export",
        "unusual_access_pattern",
        "failed_auth_spike",
        "admin_access_from_new_ip",
    ]

    if event.type in breach_indicators:
        await alert_security_team(event)
        await log_potential_breach(event)

async def report_breach(breach: DataBreach):
    """
    GDPR requires notification within 72 hours
    """
    # Internal notification
    await notify_dpo(breach)

    # Regulatory notification (if required)
    if breach.affects_personal_data:
        await prepare_supervisory_authority_notification(breach)

    # User notification (if high risk)
    if breach.risk_level == "high":
        await notify_affected_users(breach)
```

---

## Code Review Checklist for GDPR

### Data Collection
- [ ] Only necessary data collected (minimization)
- [ ] Legal basis documented for each data type
- [ ] Consent obtained before processing (where required)

### Data Subject Rights
- [ ] Data export endpoint exists (Article 15)
- [ ] Data update endpoint exists (Article 16)
- [ ] Account deletion endpoint exists (Article 17)
- [ ] Data portability format available (Article 20)

### Consent
- [ ] Granular consent options
- [ ] Easy consent withdrawal
- [ ] Consent records with timestamps

### Security
- [ ] PII encrypted at rest
- [ ] Access to PII logged
- [ ] Breach detection in place

### Retention
- [ ] Data retention periods defined
- [ ] Automatic deletion/anonymization
- [ ] Legal hold exceptions handled

---

## Data Mapping Template

Document all personal data processing:

| Data Type | Collection Point | Legal Basis | Retention | Deletion Method |
|-----------|-----------------|-------------|-----------|-----------------|
| Email | Signup | Contract | Account lifetime | Hard delete |
| Name | Signup | Contract | Account lifetime | Hard delete |
| IP Address | All requests | Legitimate interest | 30 days | Auto-purge |
| Analytics | App usage | Consent | 2 years | Anonymization |
