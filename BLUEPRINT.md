# Seeds of Success — Implementation Blueprint
## Stack: HTML + CSS + Vanilla JS + Supabase

> Goal: Turn the existing static site into a dynamic platform **without a server**, **without PHP**, and with code that is **easy to read and easy to change**.

---

## 1. Why Supabase?

- Free tier is generous (500 MB DB, 50K monthly auth users).
- Real PostgreSQL database (you can see your data in a normal table view).
- Built-in Authentication (email + password, Google login optional).
- File Storage for photos / documents.
- All accessible from the browser with **one small JS library** — no backend code.

---

## 2. Final Folder Structure (after implementation)

```
Consultancy_Project/
├── Images/                      (unchanged)
├── src/
│   ├── assets/css/
│   │   └── shared.css           ← extract common styles here (optional cleanup)
│   └── js/                      ← NEW folder, all logic lives here
│       ├── supabase-client.js   ← 1 file, 5 lines, used by every page
│       ├── auth.js              ← login / signup / logout helpers
│       ├── apply.js             ← volunteer application form
│       ├── tutor-dashboard.js   ← tutor's own page
│       ├── admin.js             ← admin approval logic
│       ├── sessions.js          ← log + view sessions
│       └── testimonials.js      ← load stories on public pages
│
├── home.html                    (unchanged, just include testimonials.js)
├── about.html                   (unchanged)
├── ourteam.html                 (unchanged)
├── ourstudents.html             ← will load testimonials dynamically
├── getinvolved.html             ← will hold the donation button
├── volunteer.html               ← form posts to Supabase via apply.js
│
├── login.html                   ← NEW (tutor & admin login)
├── signup.html                  ← NEW (tutor signup)
├── tutor-dashboard.html         ← NEW
├── admin.html                   ← NEW
└── BLUEPRINT.md                 (this file)
```

**Why this layout?** Each JS file does one thing, so when something breaks you know exactly which file to open.

---

## 3. Database Tables (create in Supabase dashboard, no SQL knowledge needed)

```diagram
╭──────────────────╮      ╭──────────────────╮
│   profiles       │      │   applications   │
│──────────────────│      │──────────────────│
│ id (uuid, PK)    │      │ id (uuid, PK)    │
│ full_name        │      │ full_name        │
│ role (tutor/admin)│     │ email            │
│ skills           │      │ phone            │
│ availability     │      │ skills           │
│ phone            │      │ message          │
│ created_at       │      │ status (pending) │
╰────────┬─────────╯      │ created_at       │
         │                 ╰──────────────────╯
         │
         │  assigned_tutor
         ▼
╭──────────────────╮      ╭──────────────────╮
│   students       │      │   sessions       │
│──────────────────│      │──────────────────│
│ id (uuid, PK)    │◀─────│ student_id (FK)  │
│ full_name        │      │ tutor_id (FK)    │
│ school           │      │ session_date     │
│ grade            │      │ notes            │
│ assigned_tutor FK│      │ progress_level   │
│ created_at       │      │ created_at       │
╰──────────────────╯      ╰──────────────────╯

╭──────────────────╮
│   testimonials   │
│──────────────────│
│ id (uuid, PK)    │
│ author_name      │
│ author_role      │
│ message          │
│ photo_url        │
│ approved (bool)  │
│ created_at       │
╰──────────────────╯
```

**Tip:** `profiles` is linked 1-to-1 with Supabase's built-in `auth.users` table (using the same `id`). You don't store passwords — Supabase handles that.

---

## 4. The "One Setup File" — `supabase-client.js`

This is the only file every page needs. ~5 lines of code:

```js
// src/js/supabase-client.js
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

export const supabase = createClient(
  "https://YOUR-PROJECT.supabase.co",   // get from Supabase dashboard
  "YOUR-ANON-PUBLIC-KEY"                // safe to expose, RLS protects data
);
```

Every other JS file just does:
```js
import { supabase } from "./supabase-client.js";
```

---

## 5. Feature → File → How It Works

### Feature 1: Tutor Account & Dashboard
- **Pages:** `signup.html`, `login.html`, `tutor-dashboard.html`
- **JS:** `auth.js`, `tutor-dashboard.js`
- **Flow:**
  1. Tutor signs up → row added to `auth.users` + `profiles` (role='tutor')
  2. On login, redirect to `tutor-dashboard.html`
  3. Dashboard reads `profiles` (own info) and `students` where `assigned_tutor = me`

### Feature 2: Admin Panel
- **Page:** `admin.html`
- **JS:** `admin.js`
- **Flow:**
  1. Manually mark one user as `role='admin'` in Supabase dashboard (one-time)
  2. Admin sees `applications WHERE status='pending'`
  3. Click **Approve** → updates status + creates a `profiles` row for the new tutor
  4. Click **Assign** on a student → sets `students.assigned_tutor`

### Feature 3: Application Management
- **Page:** modify [volunteer.html](file:///c%3A/Users/bdhar/Desktop/Consultancy_Project%20-%20Copy%20%282%29/volunteer.html)
- **JS:** `apply.js`
- **Flow:** Form submit → `supabase.from('applications').insert({...})` → show "Thank you" message. **Replaces Google Forms entirely.**

### Feature 4: Session & Progress Tracking
- **Page:** part of `tutor-dashboard.html`
- **JS:** `sessions.js`
- **Flow:**
  1. Tutor picks a student from a dropdown (only their assigned students)
  2. Fills date, notes, progress level (1–5)
  3. Insert into `sessions`
  4. Below the form, list past sessions sorted by date

### Feature 5: Donation System
- **Page:** modify [getinvolved.html](file:///c%3A/Users/bdhar/Desktop/Consultancy_Project%20-%20Copy%20%282%29/getinvolved.html)
- **JS:** none needed — just paste Razorpay's button code
- **Flow:** User clicks "Donate ₹500" → Razorpay popup → payment done. Optionally log donation to a `donations` table via webhook later.

### Feature 6: Stories & Testimonials
- **Pages:** [home.html](file:///c%3A/Users/bdhar/Desktop/Consultancy_Project%20-%20Copy%20%282%29/home.html), [ourstudents.html](file:///c%3A/Users/bdhar/Desktop/Consultancy_Project%20-%20Copy%20%282%29/ourstudents.html)
- **JS:** `testimonials.js`
- **Flow:** On page load, fetch `testimonials WHERE approved=true`, render cards with the same CSS you already have.

### Feature 7: Authentication
- **JS:** `auth.js` — wrappers around Supabase auth:
  ```js
  export async function signUp(email, password, fullName) { ... }
  export async function signIn(email, password) { ... }
  export async function signOut() { ... }
  export async function getCurrentUser() { ... }
  ```
- Supabase handles password hashing, sessions, password reset emails — you write zero security code.

---

## 6. Security (Row Level Security — RLS)

Enable RLS on every table in the Supabase dashboard, then add these plain-English policies:

| Table | Who can read | Who can write |
|---|---|---|
| `profiles` | logged-in users see their own; admin sees all | own row only; admin all |
| `applications` | admin only | anyone (public form) |
| `students` | tutor sees own assigned; admin all | admin only |
| `sessions` | tutor sees own; admin all | tutor inserts own |
| `testimonials` | anyone (public) | admin only |

Supabase has a checkbox UI for these — no SQL required for basic rules.

---

## 7. Code Style Rules (so it stays "humanised")

1. **One file = one feature.** Don't mix admin code with tutor code.
2. **Name variables like English.** `pendingApplications`, not `pa` or `data1`.
3. **Comment the "why", not the "what".**
   ```js
   // We only show approved testimonials so admin can vet content first
   .eq('approved', true)
   ```
4. **No frameworks, no build step.** Pure ES modules in the browser. Edit a file → refresh page → done.
5. **Every async call wrapped in try/catch** with a friendly user message.
6. **Reuse the existing CSS classes** — don't restyle, just add new sections that look like the rest of the site.

---

## 8. Build Order (Recommended — 8 short steps)

| Step | Task | Time |
|---|---|---|
| 1 | Create Supabase project + enable Email auth | 15 min |
| 2 | Create the 5 tables in dashboard UI | 20 min |
| 3 | Add `supabase-client.js` + test connection | 10 min |
| 4 | **Feature 3** — wire `volunteer.html` form to `applications` table | 30 min |
| 5 | **Feature 7 + 1** — `signup.html`, `login.html`, basic `tutor-dashboard.html` | 1–2 hr |
| 6 | **Feature 2** — `admin.html` with approval buttons | 1–2 hr |
| 7 | **Feature 4** — sessions form + history inside dashboard | 1 hr |
| 8 | **Feature 6** — load testimonials on public pages | 30 min |
| 9 | **Feature 5** — paste Razorpay button | 15 min |

Total: roughly **one focused weekend** of work for a basic working version.

---

## 9. What Stays the Same

- All your current HTML structure
- All your current CSS / fonts / colors / responsive design
- Your Images folder
- Your navigation menu

You're only **adding** — never rewriting what already works.

---

## 10. Hosting

Push the whole folder to:
- **Netlify** (drag-and-drop the folder), OR
- **Vercel**, OR
- **GitHub Pages**

All free. All work with static HTML + Supabase out of the box.

---

## Next Step

Tell me which step (1–9) to start, and I'll write the actual code for that step only — keeping it small, commented, and easy to edit.
