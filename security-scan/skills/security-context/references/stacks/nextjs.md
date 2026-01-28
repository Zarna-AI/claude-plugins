# Next.js Security Reference

Security patterns and common vulnerabilities specific to Next.js and React applications.

---

## Environment Variable Exposure

### Client vs Server Variables

```javascript
// DANGEROUS - Exposed to client!
// Any variable starting with NEXT_PUBLIC_ is bundled into client JS
NEXT_PUBLIC_API_KEY=sk_live_xxx  // Never do this!

// SAFE - Server-only (no NEXT_PUBLIC_ prefix)
DATABASE_URL=postgresql://...
JWT_SECRET=xxx
API_SECRET_KEY=xxx

// In code - these are server-only
const secret = process.env.JWT_SECRET;  // Only available server-side
```

### Check for Leaks

```javascript
// Vulnerable - Accessing server env on client
"use client";
export function Component() {
    // This will be undefined, but attempted access is a red flag
    const secret = process.env.DATABASE_URL;
}

// Also check: Are secrets accidentally in NEXT_PUBLIC_ vars?
// grep -r "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*PASSWORD" .env*
```

---

## API Route Security

### Authentication in API Routes

```typescript
// Vulnerable - No auth check
// app/api/users/route.ts
export async function GET() {
    const users = await db.getAllUsers();
    return Response.json(users);  // Anyone can access!
}

// Fixed - With authentication
import { auth } from "@/lib/auth";

export async function GET() {
    const session = await auth();

    if (!session) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (!session.user.isAdmin) {
        return Response.json({ error: "Forbidden" }, { status: 403 });
    }

    const users = await db.getAllUsers();
    return Response.json(users);
}
```

### Input Validation

```typescript
// Vulnerable - No validation
export async function POST(request: Request) {
    const body = await request.json();
    await db.createUser(body);  // Accepts anything!
}

// Fixed - With Zod validation
import { z } from "zod";

const CreateUserSchema = z.object({
    email: z.string().email(),
    name: z.string().min(1).max(100),
    age: z.number().int().min(0).max(150).optional(),
});

export async function POST(request: Request) {
    const body = await request.json();

    const result = CreateUserSchema.safeParse(body);
    if (!result.success) {
        return Response.json(
            { error: "Validation failed", details: result.error.issues },
            { status: 400 }
        );
    }

    await db.createUser(result.data);
    return Response.json({ success: true });
}
```

---

## Cross-Site Scripting (XSS)

### React's Built-in Protection

```jsx
// SAFE - React escapes by default
function Comment({ text }) {
    return <p>{text}</p>;  // HTML in text is escaped
}

// DANGEROUS - dangerouslySetInnerHTML
function Comment({ html }) {
    return <p dangerouslySetInnerHTML={{ __html: html }} />;  // XSS!
}

// If you MUST use dangerouslySetInnerHTML, sanitize first
import DOMPurify from "dompurify";

function Comment({ html }) {
    const clean = DOMPurify.sanitize(html);
    return <p dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

### URL-based XSS

```jsx
// Vulnerable - javascript: URLs
function Link({ href, children }) {
    return <a href={href}>{children}</a>;  // href="javascript:alert(1)"
}

// Fixed - Validate URL scheme
function Link({ href, children }) {
    const isValid = href.startsWith("/") ||
                    href.startsWith("https://") ||
                    href.startsWith("http://");

    if (!isValid) {
        console.warn("Invalid URL blocked:", href);
        return <span>{children}</span>;
    }

    return <a href={href}>{children}</a>;
}
```

---

## Server Components vs Client Components

### Data Fetching Security

```tsx
// SAFE - Server Component (default in App Router)
// Runs only on server, sensitive data never reaches client
async function Dashboard() {
    const session = await getSession();
    const secretData = await fetchSensitiveData(session.userId);

    // Only return what client needs to see
    return <div>{secretData.publicField}</div>;
}

// DANGEROUS - Client Component fetching sensitive data
"use client";
function Dashboard() {
    const [data, setData] = useState(null);

    useEffect(() => {
        // This request is visible in browser dev tools
        fetch("/api/sensitive-data")
            .then(res => res.json())
            .then(setData);
    }, []);
}
```

### Serialization Boundaries

```tsx
// Server Component passing to Client Component
// Only serializable data crosses the boundary

// WRONG - Passing sensitive data to client
async function Page() {
    const user = await getUser();  // Has password hash, etc.
    return <ClientComponent user={user} />;  // Everything serialized to client!
}

// CORRECT - Only pass what client needs
async function Page() {
    const user = await getUser();
    const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        // Don't include: passwordHash, internalId, etc.
    };
    return <ClientComponent user={safeUser} />;
}
```

---

## Server Actions Security

```tsx
// Vulnerable - No authorization
"use server";

export async function deleteUser(userId: string) {
    await db.deleteUser(userId);  // Anyone can delete any user!
}

// Fixed - With authorization
"use server";

import { auth } from "@/lib/auth";
import { z } from "zod";

const DeleteUserSchema = z.object({
    userId: z.string().uuid(),
});

export async function deleteUser(userId: string) {
    // Validate input
    const result = DeleteUserSchema.safeParse({ userId });
    if (!result.success) {
        throw new Error("Invalid user ID");
    }

    // Check authorization
    const session = await auth();
    if (!session?.user?.isAdmin) {
        throw new Error("Unauthorized");
    }

    // Rate limiting
    await rateLimit(session.user.id, "deleteUser");

    // Audit log
    await auditLog("user.delete", { userId, by: session.user.id });

    await db.deleteUser(userId);
}
```

---

## CSRF Protection

```typescript
// Next.js Server Actions have built-in CSRF protection
// But for custom API routes, verify origin

// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
    // For mutating requests, verify origin
    if (["POST", "PUT", "DELETE", "PATCH"].includes(request.method)) {
        const origin = request.headers.get("origin");
        const host = request.headers.get("host");

        if (origin && !origin.includes(host!)) {
            return NextResponse.json(
                { error: "CSRF validation failed" },
                { status: 403 }
            );
        }
    }

    return NextResponse.next();
}
```

---

## Security Headers

```typescript
// next.config.js
const securityHeaders = [
    {
        key: "X-DNS-Prefetch-Control",
        value: "on",
    },
    {
        key: "Strict-Transport-Security",
        value: "max-age=63072000; includeSubDomains; preload",
    },
    {
        key: "X-Content-Type-Options",
        value: "nosniff",
    },
    {
        key: "X-Frame-Options",
        value: "DENY",
    },
    {
        key: "X-XSS-Protection",
        value: "1; mode=block",
    },
    {
        key: "Referrer-Policy",
        value: "strict-origin-when-cross-origin",
    },
    {
        key: "Permissions-Policy",
        value: "camera=(), microphone=(), geolocation=()",
    },
];

module.exports = {
    async headers() {
        return [
            {
                source: "/:path*",
                headers: securityHeaders,
            },
        ];
    },
};
```

---

## Content Security Policy

```typescript
// middleware.ts - Dynamic CSP with nonce
import { NextResponse } from "next/server";

export function middleware(request: NextRequest) {
    const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

    const cspHeader = `
        default-src 'self';
        script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
        style-src 'self' 'nonce-${nonce}';
        img-src 'self' blob: data:;
        font-src 'self';
        object-src 'none';
        base-uri 'self';
        form-action 'self';
        frame-ancestors 'none';
        upgrade-insecure-requests;
    `.replace(/\s{2,}/g, " ").trim();

    const response = NextResponse.next();
    response.headers.set("Content-Security-Policy", cspHeader);
    response.headers.set("x-nonce", nonce);

    return response;
}
```

---

## Authentication Patterns

### Middleware Protection

```typescript
// middleware.ts
import { auth } from "@/lib/auth";

export default auth((req) => {
    const isLoggedIn = !!req.auth;
    const isAuthPage = req.nextUrl.pathname.startsWith("/login");
    const isProtectedRoute = req.nextUrl.pathname.startsWith("/dashboard");
    const isApiRoute = req.nextUrl.pathname.startsWith("/api");

    // Redirect unauthenticated users from protected routes
    if (isProtectedRoute && !isLoggedIn) {
        return Response.redirect(new URL("/login", req.nextUrl));
    }

    // Redirect authenticated users from auth pages
    if (isAuthPage && isLoggedIn) {
        return Response.redirect(new URL("/dashboard", req.nextUrl));
    }
});

export const config = {
    matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

---

## File Upload in Next.js

```typescript
// app/api/upload/route.ts
import { writeFile } from "fs/promises";
import { join } from "path";
import { v4 as uuid } from "uuid";

const ALLOWED_TYPES = ["image/jpeg", "image/png", "application/pdf"];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

export async function POST(request: Request) {
    const formData = await request.formData();
    const file = formData.get("file") as File;

    if (!file) {
        return Response.json({ error: "No file" }, { status: 400 });
    }

    // Validate size
    if (file.size > MAX_SIZE) {
        return Response.json({ error: "File too large" }, { status: 400 });
    }

    // Validate type
    if (!ALLOWED_TYPES.includes(file.type)) {
        return Response.json({ error: "Invalid file type" }, { status: 400 });
    }

    // Generate safe filename
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (!ext || !["jpg", "jpeg", "png", "pdf"].includes(ext)) {
        return Response.json({ error: "Invalid extension" }, { status: 400 });
    }

    const filename = `${uuid()}.${ext}`;
    const bytes = await file.arrayBuffer();
    const buffer = Buffer.from(bytes);

    // Store outside public directory
    const path = join(process.cwd(), "uploads", filename);
    await writeFile(path, buffer);

    return Response.json({ filename });
}
```

---

## Files to Check in Next.js Projects

| File/Pattern | What to Look For |
|--------------|------------------|
| `.env*` | NEXT_PUBLIC_ with secrets |
| `next.config.js` | Security headers, redirects |
| `middleware.ts` | Auth checks, CSP |
| `app/api/**/route.ts` | Auth, validation, error handling |
| `app/**/page.tsx` | Server vs client boundaries |
| `components/**` | dangerouslySetInnerHTML, href validation |
| `lib/auth.ts` | Session handling, JWT |
| `actions/*.ts` | Server action authorization |
