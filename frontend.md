# CipherMask – Frontend Architecture & Flow Documentation

## 1. System Overview
The CipherMask frontend is a modern, highly responsive web application built using **Next.js 16 (App Router)** and **React 19**. It leverages **Tailwind CSS v4** for styling and UI components. The frontend acts as the user interface for the DPDPA PII Masking Engine, allowing users to authenticate, view their compliance metrics, upload files (Admin only), trigger the masking pipeline, review detailed compliance reports, securely access the token vault, and monitor audit trails.

## 2. Directory & Module Structure
- `package.json` & Configuration: Defines the Next.js, React, and Tailwind setup. Uses TypeScript strictly across the codebase.
- `src/app/layout.tsx`: The root layout. Imports the `Geist` font family and wraps the entire application logic inside the `<AuthProvider>` context ensuring global state availability.
- `src/lib/api.ts`: **Core API Client**. Exports standardized asynchronous functions wrapping `fetch()`. Automatically resolves the JWT token from `localStorage` (`ciphermask_token`) and injects it as an `Authorization: Bearer` header for all requests to the FastAPI backend.
- `src/lib/auth.tsx`: **Global Authentication Context**. Manages the React Context holding the `user`, `token`, and `loading` states. Handles auto-rehydration of the session on page reload by validating the local storage token silently against the backend `/auth/me` endpoint.
- `src/components/`:
  - `Navbar.tsx`: Top navigation bar. Dynamically adjusts links based on the authenticated user's role (Admin vs Standard User).
  - `ProtectedRoute.tsx`: A Higher-Order Component style wrapper enforcing security across pages. It redirects unauthenticated traffic to `/login` and blocks standard users from `adminOnly` pages, bouncing them to the `/dashboard`.
- `src/app/`: The Next.js App Router definitions representing the pages of the application.

## 3. In-Depth Feature Architecture & Flows

### A. Authentication & Onboarding
- **Flow:** Users arrive at the generic login or register screens (inferred, standard Next.js logic). Upon submitting credentials via `login()` or `register()` inside `api.ts`, the backend responds with a JWT.
- **Context Injection:** `setAuth(token, user)` is called inside the `AuthProvider`. The token is dropped into `localStorage`, and the application state instantly reflects the user's role, unlocking the Dashboard and Navbar.

### B. The Dashboard (`/dashboard/page.tsx`)
- **Accessibility:** Protected route (accessible to all authenticated users).
- **Architecture:**
  - **Stats Layer:** Reaches out to `GET /api/stats` to populate top header cards displaying wide-scale metrics: *Total Files, Files Processed, Total PII Detected, Avg Risk Score*.
  - **Files Table:** Requests `GET /api/files` and renders a list of the user's files. Displays original filename, type, upload date, and a color-coded Status Badge (Uploaded, Processing, Completed, Failed).
  - **Admin Perks:** Admin users get a prominent "Upload File" shortcut. Standard users only see files.

### C. File Uploading (`/upload/page.tsx`)
- **Accessibility:** Protected route (`adminOnly: true`).
- **Architecture & Validation:**
  - Provides a drag-and-drop interface prioritizing UX.
  - Validates client-side against the strictly defined DPDPA extensions list (`.csv, .json, .sql, .pdf, .docx, .doc`). Prevents network waste on unsupported types.
- **Flow:**
  1. File dropped or selected.
  2. Next.js wraps the file in a `FormData` object and fires `uploadFile()`.
  3. UI enters a loading state. On success, the backend returns the database ID and the UI transitions to a "Success" state.
  4. The Admin is given a shortcut action to "Process File ->" transferring them directly to `/files/[id]`.

### D. File Processing & Compliance Reports (`/files/[id]/page.tsx`)
- **Accessibility:** Protected route.
- **Architecture:** This is a deeply reactive page dependent on the file's current status inside the database. It polls/fetches `GET /api/files` to find the target asset, and if `completed`, simultaneously fetches `GET /api/report/[id]`.
- **Dynamic Action Flow:**
  - **Status == "Uploaded"**: If Admin, renders a primary "Run Masking Pipeline" button. Clicking this triggers `POST /api/mask/[id]`. 
  - **Status == "Processing"**: Renders an indeterminate loader blocking dual-submissions.
  - **Status == "Completed"**: Unlocks the *Compliance Report*. Renders total count, risk classifications (via `RiskBadge` logic scaling from No Risk up to Critical >9.0), and a dynamic flex-box array of `pii_breakdown` mapping exact PII quantities found (e.g., AADHAAR: 14, PHONE_NUMBER: 3).
  - **Sanitized Download**: Unlocks for both standard and admin users. Fires `GET /api/files/[id]/download`, parses the response as a secure Blob, and triggers a local browser download without exposing direct file paths.
  - **Vault Forwarding**: Admins are given a "🔑 Token Vault" link navigating to `/vault/[id]`.

### E. The Secure Token Vault (`/vault/[id]/page.tsx`)
- **Accessibility:** Protected route (`adminOnly: true`).
- **Purpose:** Admin-exclusive area to review what exact strings were mapped to which tokens, enabling overriding functionality.
- **Flow:**
  - Fetches `GET /api/vault/[id]` to receive the array of `TokenMapping` objects. Displays the encrypted vault status.
  - Renders a data table with the auto-generated Tokens (`PHONE_X9A2F`) and their classification types. The original values are explicitly hidden.
  - Provides a real-time reactive search querying algorithm filtering tokens or types dynamically.
- **Decryption / Reversal Action:**
  - The Admin can click "Reveal Original Values".
  - Firing `POST /api/reverse/[id]`, the frontend expects a dictionary mapping the tokens back to their AES-256 decrypted strings.
  - The UI state `showReversed` flanks true, the top stats card switches to "🔓 Decrypted", and a new column injects into the HTML table revealing the exact sensitive PII string beside its relevant token. Re-clicking re-secures the frontend state.

### F. System Audit Logging (`/audit/page.tsx`)
- **Accessibility:** Protected route (`adminOnly: true`).
- **Purpose:** To provide total oversight and enforce DPDPA non-repudiation.
- **Flow:**
  - Fetches the massive array from `GET /api/audit-logs`.
  - Parses out the deep JSON structures found in the `details` field (e.g., printing out file_hash validations or risk_score metrics applied during a run).
  - Renders a highly dense, color-coded tracking table mapping out the Timestamp, User Email, Action (upload, mask, reverse_tokens), Target Resource, and exact origin IP Address. Built-in top-level quick filters sort the array seamlessly client-side.

## 4. UI/UX & Design Philosophy
- **Glassmorphism:** Employs `.glass-card` styling heavily to create a modern, tech-forward feel mimicking frosted glass over deep, gradient backgrounds (`globals.css` likely).
- **Progressive Disclosure:** Information isn't overloaded. For example, the detailed compliance blocks only render definitively once a file reaches completion, preventing UI jitter.
- **Micro-interactions:** Action buttons convert to loading spinners upon click, tables feature delayed stagger animations (`animate-fadeIn` utilizing `animationDelay`), and risk badges explicitly color-code the severity of DPDPA compromises (Green -> Red gradient mappings).
