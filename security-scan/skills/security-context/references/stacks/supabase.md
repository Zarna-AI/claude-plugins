# Supabase Security Reference

Security patterns and common vulnerabilities specific to Supabase (PostgreSQL, Auth, Storage, Realtime).

---

## Row Level Security (RLS)

### Critical: Always Enable RLS

```sql
-- DANGEROUS - Table without RLS
CREATE TABLE profiles (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES auth.users,
    email TEXT,
    private_data TEXT
);
-- Anyone with the anon key can read/write everything!

-- SECURE - Enable RLS
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY "Users can view own profile"
    ON profiles FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can update own profile"
    ON profiles FOR UPDATE
    USING (auth.uid() = user_id);
```

### Common RLS Mistakes

```sql
-- MISTAKE 1: Overly permissive policy
CREATE POLICY "Anyone can read" ON profiles FOR SELECT USING (true);
-- This defeats the purpose of RLS!

-- MISTAKE 2: Missing policy for operation
-- If you have SELECT policy but no INSERT policy, inserts are blocked
-- But if RLS is disabled, everything is allowed!

-- MISTAKE 3: Not checking user_id properly
CREATE POLICY "Users can delete"
    ON profiles FOR DELETE
    USING (id = auth.uid());  -- Wrong! Should check user_id, not id

-- CORRECT
CREATE POLICY "Users can delete own profile"
    ON profiles FOR DELETE
    USING (user_id = auth.uid());
```

### RLS for Related Tables

```sql
-- Posts belong to users
CREATE TABLE posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users NOT NULL,
    content TEXT
);

ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

-- Comments belong to posts
CREATE TABLE comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID REFERENCES posts NOT NULL,
    user_id UUID REFERENCES auth.users NOT NULL,
    content TEXT
);

ALTER TABLE comments ENABLE ROW LEVEL SECURITY;

-- Users can only comment on posts they can see
CREATE POLICY "Users can comment on visible posts"
    ON comments FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM posts
            WHERE posts.id = post_id
            -- This respects the posts RLS policies
        )
        AND auth.uid() = user_id
    );
```

---

## Authentication Security

### Secure Auth Configuration

```typescript
// supabase client setup
import { createClient } from "@supabase/supabase-js";

// Client-side (browser) - use anon key
const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

// Server-side with user context - use anon key + user's JWT
const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
        global: {
            headers: {
                Authorization: `Bearer ${userJwt}`,
            },
        },
    }
);

// Server-side admin operations - use service role key
// NEVER expose this to the client!
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!  // Server only!
);
```

### Auth Vulnerabilities to Check

```typescript
// VULNERABLE - Using service role key on client
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
// Service role bypasses RLS! Never use on client.

// VULNERABLE - Not validating JWT on server
async function handler(req) {
    const { data } = await supabase.from("profiles").select();
    // This uses anon permissions, not user's permissions
}

// SECURE - Validate and use user's JWT
async function handler(req) {
    const token = req.headers.authorization?.split(" ")[1];

    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
        return unauthorized();
    }

    // Create client with user's session
    const userSupabase = createClient(url, anonKey, {
        global: { headers: { Authorization: `Bearer ${token}` } },
    });

    const { data } = await userSupabase.from("profiles").select();
    // Now RLS policies are enforced for this user
}
```

---

## Storage Security

### Bucket Policies

```sql
-- Storage buckets need RLS too!

-- Public bucket (anyone can read)
CREATE POLICY "Public read access"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'public-assets');

-- Private bucket (only owner)
CREATE POLICY "Users can access own files"
    ON storage.objects FOR SELECT
    USING (
        bucket_id = 'private-files'
        AND auth.uid()::text = (storage.foldername(name))[1]
    );

-- Upload policy with validation
CREATE POLICY "Users can upload to own folder"
    ON storage.objects FOR INSERT
    WITH CHECK (
        bucket_id = 'uploads'
        AND auth.uid()::text = (storage.foldername(name))[1]
        AND (storage.extension(name) IN ('jpg', 'png', 'pdf'))
    );
```

### Storage Path Traversal

```typescript
// VULNERABLE - User controls full path
async function uploadFile(userId: string, filename: string, file: File) {
    await supabase.storage
        .from("uploads")
        .upload(filename, file);  // filename = "../admin/secrets.txt" ?
}

// SECURE - Construct safe path
async function uploadFile(userId: string, filename: string, file: File) {
    // Sanitize filename
    const safeName = filename.replace(/[^a-zA-Z0-9.-]/g, "_");
    const path = `${userId}/${Date.now()}_${safeName}`;

    await supabase.storage
        .from("uploads")
        .upload(path, file);
}
```

---

## API Key Security

### Key Types and Usage

| Key | Where to Use | RLS | Danger Level |
|-----|--------------|-----|--------------|
| `anon` key | Client-side | ✅ Enforced | Low (if RLS is correct) |
| `service_role` key | Server-side only | ❌ Bypassed | CRITICAL if exposed |

### Check for Key Exposure

```javascript
// CRITICAL - Service role key in client code
// Search for these patterns:
const supabase = createClient(url, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

// Check if it's service role by decoding:
// Service role JWT has "role": "service_role"
// Anon key JWT has "role": "anon"

// Files to check:
// - Any file in /app, /pages, /components (client code)
// - Environment files committed to git
// - .env.local.example files
```

---

## Realtime Security

### Channel Authorization

```typescript
// VULNERABLE - Anyone can listen to any channel
const channel = supabase.channel("private-room");

// SECURE - Use RLS for database changes
// Realtime respects RLS policies for postgres_changes

// For custom channels, use Realtime Authorization
// In supabase/config.toml:
// [realtime]
// enabled = true
// jwt_secret = "your-jwt-secret"

// Then validate on subscription
const channel = supabase.channel("room:123", {
    config: {
        presence: {
            key: userId,  // Identify user
        },
    },
});
```

---

## Database Functions Security

### SECURITY DEFINER vs SECURITY INVOKER

```sql
-- SECURITY INVOKER (default, safer)
-- Runs with the permissions of the calling user
CREATE FUNCTION get_my_data()
RETURNS TABLE (id uuid, data text)
LANGUAGE plpgsql
SECURITY INVOKER  -- Uses caller's permissions
AS $$
BEGIN
    RETURN QUERY SELECT id, data FROM my_table;
END;
$$;

-- SECURITY DEFINER (dangerous if misused)
-- Runs with the permissions of the function creator
CREATE FUNCTION admin_get_all_users()
RETURNS TABLE (id uuid, email text)
LANGUAGE plpgsql
SECURITY DEFINER  -- Bypasses RLS!
AS $$
BEGIN
    RETURN QUERY SELECT id, email FROM auth.users;
END;
$$;

-- If you must use SECURITY DEFINER, add checks:
CREATE FUNCTION admin_get_all_users()
RETURNS TABLE (id uuid, email text)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Manual authorization check
    IF NOT EXISTS (
        SELECT 1 FROM user_roles
        WHERE user_id = auth.uid() AND role = 'admin'
    ) THEN
        RAISE EXCEPTION 'Unauthorized';
    END IF;

    RETURN QUERY SELECT id, email FROM auth.users;
END;
$$;
```

---

## Edge Functions Security

```typescript
// supabase/functions/my-function/index.ts

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

serve(async (req) => {
    // CORS handling
    if (req.method === "OPTIONS") {
        return new Response("ok", {
            headers: {
                "Access-Control-Allow-Origin": "https://myapp.com",  // Not *
                "Access-Control-Allow-Methods": "POST",
                "Access-Control-Allow-Headers": "authorization, content-type",
            },
        });
    }

    // Validate JWT
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
        return new Response(JSON.stringify({ error: "No auth" }), { status: 401 });
    }

    const supabase = createClient(
        Deno.env.get("SUPABASE_URL")!,
        Deno.env.get("SUPABASE_ANON_KEY")!,
        {
            global: { headers: { Authorization: authHeader } },
        }
    );

    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) {
        return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401 });
    }

    // Now user is authenticated, proceed with business logic
});
```

---

## Common Supabase Security Checklist

### Must Check

- [ ] RLS enabled on ALL tables
- [ ] Service role key not exposed to client
- [ ] Storage buckets have appropriate policies
- [ ] Auth settings configured (password requirements, etc.)
- [ ] Database functions reviewed for SECURITY DEFINER
- [ ] Edge functions validate JWT

### Configuration to Review

```sql
-- Check RLS status for all tables
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public';

-- Check existing policies
SELECT * FROM pg_policies WHERE schemaname = 'public';

-- Check for tables without policies (RLS enabled but no policies = no access)
-- This is safe but might indicate incomplete setup
```

---

## Files to Check in Supabase Projects

| File/Pattern | What to Look For |
|--------------|------------------|
| `supabase/migrations/*.sql` | RLS policies, SECURITY DEFINER |
| `.env*` | Service role key exposure |
| `lib/supabase.ts` | Which key is used where |
| `supabase/functions/**` | JWT validation, CORS |
| `supabase/config.toml` | Auth settings, realtime config |
