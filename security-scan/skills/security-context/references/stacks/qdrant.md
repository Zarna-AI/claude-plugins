# Qdrant Security Reference

Security patterns and common vulnerabilities specific to Qdrant vector database.

---

## Overview

Qdrant is a vector similarity search engine. Security concerns focus on:
- API access control
- Data exposure through similarity search
- Network security
- Resource exhaustion

---

## Authentication & API Security

### API Key Authentication

```python
# VULNERABLE - No authentication
from qdrant_client import QdrantClient

client = QdrantClient(host="localhost", port=6333)
# Anyone with network access can query/modify data

# SECURE - With API key
client = QdrantClient(
    host="qdrant.example.com",
    port=6333,
    api_key=os.environ["QDRANT_API_KEY"],
    https=True  # Always use HTTPS in production
)
```

### Environment Configuration

```bash
# Qdrant server config (config.yaml)
service:
  api_key: ${QDRANT_API_KEY}  # Set via environment
  enable_tls: true

# NEVER hardcode API keys
# NEVER commit config with actual keys
```

---

## Network Security

### Exposed Qdrant Instance

```yaml
# DANGEROUS - Binding to all interfaces without auth
service:
  host: 0.0.0.0
  port: 6333
  # No api_key configured!

# SECURE - Localhost only or with auth
service:
  host: 127.0.0.1  # Local only
  port: 6333
  api_key: ${QDRANT_API_KEY}

# Or with proper network security
service:
  host: 0.0.0.0
  port: 6333
  api_key: ${QDRANT_API_KEY}
  enable_tls: true
```

### Firewall Rules

```bash
# Ensure Qdrant port is not publicly accessible
# Check cloud security groups / firewall rules

# Only allow access from application servers
# Not from 0.0.0.0/0 (internet)
```

---

## Data Security

### Sensitive Data in Vectors

```python
# CONCERN: What data is being embedded?
# Vectors can potentially be reversed to reveal original content

# If storing sensitive document embeddings:
# 1. Consider what metadata is stored with vectors
# 2. Implement access control at application level
# 3. Don't store PII in searchable metadata

# VULNERABLE - Storing sensitive metadata
client.upsert(
    collection_name="documents",
    points=[
        {
            "id": 1,
            "vector": embedding,
            "payload": {
                "content": "Full document text with PII",  # Searchable!
                "user_ssn": "123-45-6789",  # Very bad!
                "email": "user@example.com"
            }
        }
    ]
)

# BETTER - Minimal metadata, reference to secure storage
client.upsert(
    collection_name="documents",
    points=[
        {
            "id": 1,
            "vector": embedding,
            "payload": {
                "document_id": "doc_123",  # Reference only
                "category": "financial",
                "user_id": "user_456"  # For filtering, not PII
            }
        }
    ]
)
```

### Payload Filtering Security

```python
# Ensure users can only search their own data
def search_user_documents(user_id: str, query_vector: list):
    return client.search(
        collection_name="documents",
        query_vector=query_vector,
        query_filter={
            "must": [
                {"key": "user_id", "match": {"value": user_id}}
            ]
        },
        limit=10
    )

# VULNERABLE - No user filtering
def search_all_documents(query_vector: list):
    return client.search(
        collection_name="documents",
        query_vector=query_vector,
        limit=10
    )  # Returns any user's documents!
```

---

## Injection & Input Validation

### Collection Name Injection

```python
# VULNERABLE - User input in collection name
@app.get("/search/{collection}")
async def search(collection: str, query: str):
    return client.search(
        collection_name=collection,  # User-controlled!
        query_vector=embed(query)
    )
# Attacker could access: /search/admin_secrets

# SECURE - Whitelist collections
ALLOWED_COLLECTIONS = {"documents", "products", "faq"}

@app.get("/search/{collection}")
async def search(collection: str, query: str):
    if collection not in ALLOWED_COLLECTIONS:
        raise HTTPException(status_code=400, detail="Invalid collection")

    return client.search(
        collection_name=collection,
        query_vector=embed(query)
    )
```

### Filter Injection

```python
# VULNERABLE - User-controlled filters
@app.post("/search")
async def search(filters: dict, query: str):
    return client.search(
        collection_name="documents",
        query_vector=embed(query),
        query_filter=filters  # User controls entire filter!
    )

# SECURE - Construct filters server-side
@app.post("/search")
async def search(category: str, query: str, user: User = Depends(get_user)):
    # Validate category
    if category not in VALID_CATEGORIES:
        raise HTTPException(status_code=400)

    return client.search(
        collection_name="documents",
        query_vector=embed(query),
        query_filter={
            "must": [
                {"key": "user_id", "match": {"value": user.id}},
                {"key": "category", "match": {"value": category}}
            ]
        }
    )
```

---

## Resource Exhaustion

### Query Limits

```python
# VULNERABLE - No limits
@app.get("/search")
async def search(query: str, limit: int):
    return client.search(
        collection_name="documents",
        query_vector=embed(query),
        limit=limit  # limit=1000000?
    )

# SECURE - Enforce limits
MAX_RESULTS = 100

@app.get("/search")
async def search(query: str, limit: int = 10):
    safe_limit = min(max(1, limit), MAX_RESULTS)

    return client.search(
        collection_name="documents",
        query_vector=embed(query),
        limit=safe_limit
    )
```

### Rate Limiting

```python
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.get("/search")
@limiter.limit("60/minute")
async def search(request: Request, query: str):
    # Embedding generation and vector search are expensive
    pass
```

---

## Backup & Recovery Security

```bash
# Qdrant snapshots may contain sensitive data
# Secure snapshot storage:

# 1. Encrypt snapshots at rest
# 2. Restrict access to snapshot storage
# 3. Don't expose snapshot endpoints publicly

# Check if snapshot API is accessible:
curl https://qdrant.example.com:6333/collections/documents/snapshots
# Should require authentication!
```

---

## TLS/HTTPS Configuration

```yaml
# Qdrant config for TLS
service:
  enable_tls: true

tls:
  cert: /path/to/cert.pem
  key: /path/to/key.pem
```

```python
# Client with TLS verification
client = QdrantClient(
    host="qdrant.example.com",
    port=6333,
    https=True,
    api_key=os.environ["QDRANT_API_KEY"]
)

# NEVER disable TLS verification in production
# verify=False is dangerous
```

---

## Security Checklist for Qdrant

### Infrastructure
- [ ] Qdrant not exposed to public internet
- [ ] API key authentication enabled
- [ ] TLS/HTTPS enabled
- [ ] Firewall rules restrict access to app servers only
- [ ] Snapshots stored securely

### Application
- [ ] API key stored in environment variables
- [ ] Collection names validated/whitelisted
- [ ] User data properly filtered (multi-tenant isolation)
- [ ] Query limits enforced
- [ ] Rate limiting implemented
- [ ] No sensitive PII in searchable payloads

### Monitoring
- [ ] Access logs enabled
- [ ] Alerts for unusual query patterns
- [ ] Failed auth attempts monitored

---

## Files to Check

| File/Pattern | What to Look For |
|--------------|------------------|
| `config.yaml`, `config.toml` | API key, TLS settings |
| `.env*` | QDRANT_API_KEY, QDRANT_URL |
| `**/qdrant*.py` | Client initialization, auth |
| API routes using Qdrant | Filter construction, limits |
| Docker/K8s configs | Port exposure, secrets |
