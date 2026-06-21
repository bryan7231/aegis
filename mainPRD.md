# ChainBreak — Product Requirements Document

**The attack-path visualizer for the open-source tools real people depend on.**

| | |
|---|---|
| **Document owner** | marativish@gmail.com |
| **Status** | Draft v2.0 — full-stack spec |
| **Last updated** | 2026-06-20 |
| **Event** | The Cybersecurity Innovation Hackathon — Issue #1 |
| **Build window** | One weekend (Fri night → Sun demo) |

---

## 1. Executive Summary

ChainBreak is a web tool that takes a project's dependency file, identifies its **known** vulnerabilities by matching installed versions against public vulnerability databases, and renders them as an **interactive 3D attack-path graph** instead of a flat list. It then chains individually "low-severity" flaws into realistic attack paths, identifies the **bridge nodes** that multiple attack paths route through, and produces a **minimal, ordered remediation plan** — "fix these 2 packages and 8 of 9 attack paths collapse."

The data is deterministic and verifiable (anyone can reproduce the CVE list with `osv-scanner`). The innovation is the graph and the chained triage on top of it: ChainBreak answers a question existing scanners do not — *not* "what's wrong," but **"what's the smallest thing I can fix to break the most attacks?"**

---

## 2. Problem Statement

### The user's reality
A student or solo developer ships a public tool that real people use — a Discord bot, a club-event tracker, a local food-bank database. They run `npm audit` (or get a GitHub alert) and see **30 warnings sorted by severity**. They have no security background. The list is overwhelming, context-free, and gives no sense of *what actually matters*. So they do the rational thing for a busy person: **they ignore all of it.**

### Why existing tools fail this user
- **They treat each vulnerability as an isolated incident.** Snyk, Dependabot, and `npm audit` give you a flat list. They never show how three "minor" flaws combine into a full account takeover.
- **They sort by CVSS severity**, which is context-free. A CVSS 9.8 "Critical" in a code path that's unreachable matters less than a CVSS 6.1 "Medium" that sits on the only route to your secrets. The list can't tell the difference.
- **They tell you to fix everything**, which a solo maintainer can't and won't do. They don't tell you the *minimum* set of fixes that eliminates the *most* risk.

### The gap ChainBreak fills
The real-world danger is the **chain**: a loose permission + an outdated package + an exposed capability, combined. ChainBreak is built around the big picture — it connects unrelated minor flaws into attack paths, shows them spatially, and reduces the response to a 2-step checklist.

---

## 3. Target Customer

**Primary:** Independent developers and student creators maintaining **public, open-source tools that other people use** — Discord bots, school-club apps, small nonprofit databases, popular utilities.

**Why they're the right customer (hackathon rule: "build for a customer you can actually reach"):**
- Reachable: this is us, our classmates, our project repos.
- Real need: they ship code real people depend on, with zero security budget or expertise.
- No privileged access required: ChainBreak works on any public dependency file. It needs **nothing** from a company's private systems.
- Clear adoption reason: it turns an ignored wall of warnings into a 2-minute, 2-step action.

**Secondary (future):** small startups and nonprofits without a security team; bootcamp/CS-course instructors teaching secure development.

### Personas
- **"Maya," CS sophomore, Discord-bot maintainer.** 1,200 users on her bot. Got a GitHub security alert, doesn't understand it, scared to upgrade anything in case it breaks. Wants: "just tell me what to click."
- **"Devon," nonprofit volunteer dev.** Maintains a food-bank inventory app. One person, no security review. Wants confidence the app won't leak donor data, in language he understands.

---

## 4. Goals, Non-Goals, and Success Metrics

### Goals
1. Detect known vulnerabilities in a project's dependencies, grounded in public databases (zero hallucinated findings).
2. Render the **entire system** as a meaningful, non-linear, **3D** attack-path graph.
3. Chain low-severity flaws into realistic multi-step attack paths.
4. Triage by real-world risk (reachability + bridge centrality + exploit likelihood), **not** raw CVSS.
5. Output a **minimal, ordered, copy-pasteable** remediation plan.
6. Be demoable and believable in 3 minutes.

### Non-Goals (explicit scope honesty — we will say these out loud)
- ❌ We do **not** discover novel/0-day vulnerabilities.
- ❌ We do **not** perform static analysis of source code for injection/XSS/etc.
- ❌ We do **not** prove the vulnerable code path is actually executed at runtime (true reachability analysis is out of scope; our "reachability" is dependency-graph reachability, stated as such).
- ❌ We do **not** auto-apply fixes or open PRs (MVP outputs commands; auto-PR is a stretch goal).
- ❌ We do **not** require access to any private/company system.

### Success Metrics
| Metric | Target |
|---|---|
| Detection accuracy vs. `osv-scanner` on the same lockfile | 100% match (same data source) |
| Hallucinated vulnerabilities | **0** (architecturally impossible — see §7) |
| Time from paste → rendered graph | < 15 seconds for a typical project |
| Graph is non-linear & 3D | Force-directed 3D layout, never collinear |
| "Aha" moment lands in demo | Judge understands "fix 2, break 8/9" in < 30s |
| Remediation plan is actionable | Every step = exact `npm install pkg@version` command |

---

## 5. User Stories

- **US-1:** As Maya, I sign in with GitHub and paste my `package-lock.json` and within seconds see a 3D map of my whole project with the dangerous parts lit up, so I'm not staring at a list of jargon.
- **US-2:** As Maya, I rotate the graph and *see* how an attacker would get from my public webhook to my bot token, so I finally understand *why* it matters.
- **US-3:** As Devon, I get a ranked list that tells me the **2 upgrades** that matter most, with the exact commands, so I can fix the biggest risks in 5 minutes.
- **US-4:** As Devon, I see that a "Critical" warning I was panicking about is actually low priority in *my* system, so I stop wasting effort on the wrong thing.
- **US-5:** As a judge, I click any "clean" cluster and expand it to confirm the whole dependency tree is really represented, so I trust the tool is complete and honest.
- **US-6:** As Maya, I can return to my dashboard and see all previous projects I've analyzed, so I don't lose my work between sessions.
- **US-7:** As Devon, I click "Analyze" and get a plain-English vulnerability report generated by Claude, which I can read before diving into the graph.
- **US-8:** As Maya, I click any graph node and see a detail panel with the full CVE info, what capability it grants an attacker, and which other nodes it connects to.
- **US-9:** As Devon, I click "Plan of Action" and get an ordered, OSV-backed remediation checklist I can copy straight into my terminal.
- **US-10:** As Maya, I view the Vulnerabilities page and see all CVEs ranked from highest-priority (most graph connections) to lowest, not by raw CVSS score.

---

## 6. How Detection Works (The Grounding Layer)

**We do not find vulnerabilities — we match installed versions against public catalogs of already-discovered flaws.** Detection is a deterministic lookup, not analysis or inference.

### Pipeline
```
package-lock.json ──► exact pinned versions ──► OSV batch query ──► semver range match ──► confirmed CVEs ──► enrich (EPSS, KEV)
```

1. **Parse the lockfile** (`package-lock.json`) to get the *exact resolved version* of every direct and transitive dependency (e.g. `lodash@4.17.11`, not the `^4.0.0` range). The lockfile is the ground truth of what's actually installed.
2. **Batch-query OSV** (`https://api.osv.dev/v1/querybatch`) — free, no API key. OSV aggregates the GitHub Advisory DB, npm advisories, and NVD into one normalized feed.
3. **Semver range match.** Each OSV advisory lists affected ranges with `introduced`/`fixed` boundaries. We confirm a vulnerability only if the installed version falls in `[introduced, fixed)` using proper semantic-version comparison (never string compare). OSV also returns the **fixed version**, which becomes the remediation target.
4. **Enrich each confirmed CVE** by ID:
   - **EPSS** (`first.org/data/v1/epss`) — probability the CVE is exploited in the wild within 30 days.
   - **CISA KEV** catalog — binary flag for "actively exploited right now" (auto-max priority).

### Data sources (all free, public, no privileged access)
| Source | Provides | Auth |
|---|---|---|
| **OSV** (osv.dev) | CVE/GHSA IDs, affected ranges, CVSS vectors, fixed versions | None |
| **EPSS** (FIRST.org) | Exploitation-probability score per CVE | None |
| **CISA KEV** | Known-exploited-in-the-wild flag | None (JSON download) |

**Reproducibility guarantee:** anyone can paste the same lockfile into `osv-scanner` and get the identical CVE list. The detection data is intentionally boring and trustworthy.

---

## 7. Why There Are Zero Hallucinated Vulnerabilities

The LLM never decides whether something is vulnerable. **A graph node exists only if OSV confirmed it.** The LLM operates one layer down, on the already-confirmed set:
- It reads each confirmed CVE's official description + CVSS vector and extracts `{preconditions, capabilities}` → the `enables` edges.
- It reasons about whether one flaw's *output* satisfies another flaw's *precondition* → the `chains_to` edges.

**The LLM draws edges between confirmed nodes; it never adds a node.** Delete the LLM entirely and you still have a correct, real vulnerability list — you just lose the chaining narrative. This is the architectural answer to "is this real?"

---

## 8. The Graph Specification

This is the core differentiator. Requirements: **the entire system must be represented**, the graph must be **meaningful and non-linear**, and it must be **3-dimensional**.

### 8.1 Node types (Z = kill-chain depth, top → bottom)
| Z layer | Node type | Source |
|---|---|---|
| Z0 | `entry_point` | App's public surface (webhook, message handler) |
| Z1 | `direct_dep` | Declared in package.json |
| Z2 | `transitive_dep` | Resolved via lockfile (full tree) |
| Z2 | `clean_cluster` | Collapsed summary of a CVE-free subtree (expandable) |
| Z3 | `cve` | Confirmed CVE from OSV, colored by triage tier |
| Z4 | `capability` | What an attacker gains (RCE, file-read, credential exfil) |
| Z5 | `asset` | Crown jewel (bot token, host shell, availability) |

### 8.2 Edge types
| Edge | From → To | Derived by |
|---|---|---|
| `depends_on` | pkg → pkg | Lockfile (the dependency tree — branches naturally) |
| `vulnerable_to` | pkg → cve | OSV match |
| `enables` | cve → capability | CVSS impact vector + LLM extraction |
| `chains_to` | capability → cve | Precondition satisfaction (CVSS + LLM) — the cross-links |
| `compromises` | capability → asset | LLM reasoning over confirmed capabilities |

### 8.3 Why it is non-linear and meaningful
- **The dependency tree branches by nature** (one direct dep pulls in many transitive deps). Embedding CVEs inside it inherits that fan-out — never a line.
- **`chains_to` cross-links** loop a Z4 capability back up to a Z3 CVE in a *different* branch (e.g. prototype-pollution from `lodash` becomes the gadget that turns an `ejs` template flaw into RCE). These cross-branch links create the funnel structure.
- **Force-directed layout physically cannot produce collinear nodes** — coupled subsystems cluster into visible blobs; the bridge node is literally where branches converge.

### 8.4 The third dimension is *semantic* (not decorative)
- **Z position = kill-chain depth.** Attack flows top (entry points) → bottom (crown-jewel assets). Rotating the model shows the attack descending through the system.
- **X/Y = force-directed clustering** by module/coupling.

### 8.5 Entire-system representation + readability ("collapse clean subtrees")
- The **full tree is present and reachable**. A subtree with **zero CVEs in any descendant** renders as one `clean_cluster` summary node ("📦 +23 clean deps") that **expands on click** — nothing is deleted, only folded.
- Collapse rule: `collapse(subtree) if no descendant has a CVE`. Any subtree containing a CVE auto-expands, so every attack chain is visible by default. Judges can expand any cluster to verify completeness.
- **Centrality is computed on the full graph** — collapsing is display-only, so bridge scores stay honest.

### 8.6 Visual encoding
| Channel | Encodes |
|---|---|
| Z position | Kill-chain depth |
| X/Y position | Force-directed cluster |
| Node size | Bridge centrality (betweenness) |
| Node color | Triage tier (red critical → grey clean) |
| Edge glow | Active attack path (everything else faint) |
| Animation | On fix: glowing paths blink out, bridge node greys |

---

## 9. Triage Model (Risk, Not Raw CVSS)

Each CVE node is scored on four axes and bucketed into a tier. **The headline metric is bridge centrality, not CVSS.**

| Axis | Computed from | Why |
|---|---|---|
| **Base severity** | CVSS base score (OSV) | Raw danger |
| **Reachability** | Path exists from an `entry_point` node | Unreachable critical = noise |
| **Bridge centrality** | Betweenness centrality (`networkx`) over attack paths | How many attacks route through this node |
| **Exploit likelihood** | EPSS score; KEV = auto-max | Is it exploited in reality? |

**Composite priority → tiers:** Critical / High / Medium / Low / Noise.

A CVSS 9.8 package whose only dangerous route dead-ends once a downstream bottleneck is fixed is correctly downgraded to **Low** — the anti-flat-list insight judges respond to.

---

## 10. Remediation Algorithm (Minimal Fix Set)

Convert the graph into the **smallest ordered set of upgrades that breaks the most attack paths**, via greedy set-cover:

1. For each vulnerable package, OSV provides the **fixed version** → the fix is `npm install pkg@fixedversion`.
2. For each candidate fix, compute **how many entry→asset attack paths it eliminates** (remove the node, recount paths).
3. **Greedily pick the fix that breaks the most paths**, recompute, repeat → a minimal fix set.
4. Emit an ordered checklist; each step states paths broken, CVEs closed, the exact command, and a verification command.

**Output headline format:**
> "You have N vulnerable packages and M attack paths. Fix K packages and X of M paths collapse — including every path to remote code execution and every path to your secrets. What remains is [low-severity residue]."

---

## 11. LLM Usage

**Provider: Claude.** The LLM's role is **vulnerability narrative reporting**, **edge reasoning over confirmed CVEs**, and **plan-of-action narration** — never detection. Nodes come only from OSV.

| Task | Trigger | Model | Rationale |
|---|---|---|---|
| **Full vulnerability report** | "Analyze DB" button | `claude-opus-4-8` | Best reasoning; synthesizes the full confirmed CVE set into a clear narrative, chain summary, and highest-risk path identification |
| **Capability extraction** (per CVE) | Inside analyze pipeline | `claude-haiku-4-5-20251001` | High-volume, cheap ($1/$5 per MTok), fast; structured JSON extraction |
| **Plan of Action narration** | "Generate Plan" button | `claude-sonnet-4-6` | Explains *why* each fix matters in plain English; synthesis quality matters here |

- Use **structured outputs** for extraction and plan steps so results are validated JSON, parsed with `json.loads` — never string-matched.
- LLM input per CVE is constrained to the **official CVE description + CVSS vector**. It cannot invent CVEs.
- The Opus 4.8 analyze call receives the **full confirmed CVE list** for the project (not individual CVEs), enabling it to reason about chains holistically.
- Cost for a single-project demo is cents — do not over-optimize; spend effort on the graph and UX.

> Model IDs: Opus 4.8 → `claude-opus-4-8`; Haiku 4.5 → `claude-haiku-4-5-20251001`; Sonnet 4.6 → `claude-sonnet-4-6`.

---

## 12. System Architecture

```
┌──────────────────────────────────────────┐   REST/JSON   ┌──────────────────────────────────────┐
│  React + Vite SPA                        │ ────────────► │  FastAPI (Python)                     │
│                                          │               │  ┌────────────────────────────────┐  │
│  Pages:                                  │ ◄──────────── │  │ POST /projects                  │  │
│  • /login         GitHub OAuth           │  graph JSON   │  │ GET  /projects                  │  │
│  • /dashboard     project history        │               │  │ POST /projects/{id}/analyze     │  │
│  • /projects/:id  graph + triage         │               │  │ GET  /projects/{id}/vulns       │  │
│  • /vulns/:id     vulnerability list     │               │  │ POST /projects/{id}/plan        │  │
│  • /graph/:id     3D visualization       │               │  └────────────────────────────────┘  │
│                                          │               │         │ confirmed CVEs only         │
│  UI Kit: shadcn/ui + Tailwind            │               │         ▼                             │
│  Auth:  Better Auth (GitHub OAuth)       │               │   Claude Opus 4.8 (analyze report)    │
│  3D:    react-force-graph-3d             │               │   Claude Haiku 4.5 (CVE extraction)   │
└──────────────────────────────────────────┘               │   Claude Sonnet 4.6 (narration)       │
                                                           └──────────────────────────────────────┘
                                                                     │
                                               OSV API · EPSS API · CISA KEV (all free, public)
```

### Tech stack
| Layer | Choice | Why |
|---|---|---|
| Backend | **Python + FastAPI** | OSV/EPSS calls + `networkx` graph algorithms; clean async support |
| Auth | **Better Auth** (server-side library) | Drop-in GitHub OAuth; session management; works with FastAPI |
| Graph engine | **networkx** | Betweenness centrality, path enumeration, set-cover built in |
| Frontend | **React + Vite** | Fast dev experience; Vite HMR |
| UI components | **shadcn/ui + Tailwind CSS** | Accessible, pre-built components; utility-first styling |
| 3D graph | **react-force-graph-3d** | Three.js/WebGL; force-directed; handles hundreds of nodes |
| LLM — analyze | **Claude Opus 4.8** (`claude-opus-4-8`) | Best reasoning for full vulnerability narrative report |
| LLM — extract | **Claude Haiku 4.5** (`claude-haiku-4-5-20251001`) | High-volume structured CVE capability extraction |
| LLM — narrate | **Claude Sonnet 4.6** (`claude-sonnet-4-6`) | Plan-of-action synthesis and human-readable chain stories |
| Semver | Python `packaging` / `semver` | Correct range matching per ecosystem |
| DB | **SQLite** (MVP) / PostgreSQL (prod) | Store projects, users, cached analysis results |

### Multi-ecosystem support (input formats)
| Ecosystem | Accepted files | OSV ecosystem key |
|---|---|---|
| **npm** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `npm` |
| **PyPI** | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | `PyPI` |
| **Go** | `go.sum` | `Go` |
| **Rust** | `Cargo.lock` | `crates.io` |
| **RubyGems** | `Gemfile.lock` | `RubyGems` |

The backend auto-detects the ecosystem from the filename. Each parser normalizes to `{name, version, ecosystem}` tuples before the OSV query — the rest of the pipeline is identical regardless of language.

### Frontend design
The UI is designed in **Figma** first, then implemented in React. The Figma dashboard covers:
- Landing / login page (GitHub OAuth CTA)
- Dashboard (project cards, "New Project" button)
- Project detail shell (tab bar: Graph · Vulnerabilities · Triage · Plan)
- Vulnerability list layout (sortable table)
- Graph canvas + node detail drawer
- Triage panel (priority-ordered list)
- Plan of Action view (ordered checklist with copy buttons)

shadcn/ui components used: `Card`, `Button`, `Table`, `Badge`, `Sheet` (drawer), `Tabs`, `Dialog`, `Skeleton`, `Toast`.

---

## 13. Data Model (API Contract)

All endpoints require a valid session (Better Auth cookie/token). Auth endpoints handled by Better Auth's built-in routes.

### Auth endpoints (Better Auth — auto-generated)
```
GET  /auth/github          → redirect to GitHub OAuth
GET  /auth/github/callback → exchange code, set session cookie
POST /auth/logout          → clear session
GET  /auth/session         → { user: { id, email, github_login, avatar_url } }
```

### Projects endpoints

**`POST /api/projects`** — Create a new project
```json
// Request
{ "name": "my-discord-bot", "files": [{ "filename": "package-lock.json", "content": "..." }] }

// Response
{ "id": "proj_abc123", "name": "my-discord-bot", "ecosystem": "npm",
  "created_at": "2026-06-20T10:00:00Z", "status": "pending" }
```

**`GET /api/projects`** — List all projects for the authenticated user
```json
[
  { "id": "proj_abc123", "name": "my-discord-bot", "ecosystem": "npm",
    "created_at": "2026-06-20T10:00:00Z", "status": "analyzed",
    "summary": { "vulnerable_packages": 5, "attack_paths": 9, "fixes_needed": 2 } }
]
```

### Analyze endpoint

**`POST /api/projects/{id}/analyze`** — Run full analysis using **Claude Opus 4.8**

This is the "Analyze DB" button. On call:
1. Parses the stored lockfile(s) per ecosystem
2. Batch-queries OSV for all confirmed CVEs
3. Enriches with EPSS + CISA KEV
4. Sends confirmed CVE list to **Claude Opus 4.8** with this prompt contract:
   - Input: list of `{cve_id, description, cvss_vector, epss, kev, package, version}`
   - Output: structured JSON `{ narrative, capabilities[], chain_summary, highest_risk_path }`
5. Builds networkx graph (nodes + edges + centrality)
6. Runs greedy set-cover for remediation
7. Stores result; returns graph JSON

```json
// Response
{
  "report": {
    "narrative": "Your project has 5 vulnerable packages forming 9 attack paths...",
    "chain_summary": "A prototype-pollution flaw in lodash combined with an EJS template injection creates a full RCE path to your host shell.",
    "highest_risk_path": "webhook → express → ejs → RCE → host"
  },
  "nodes": [
    { "id": "ejs@3.1.6", "type": "direct_dep", "z": 1, "label": "ejs",
      "version": "3.1.6", "tier": "critical", "bridge_score": 0.92,
      "connections": 6 },
    { "id": "CVE-2022-29078", "type": "cve", "z": 3, "cvss": 9.8,
      "epss": 0.71, "kev": false, "tier": "critical", "fixed_version": "3.1.10",
      "connections": 4 },
    { "id": "clean_cluster_express", "type": "clean_cluster", "z": 2,
      "count": 23, "collapsed": true, "children": ["..."] }
  ],
  "edges": [
    { "source": "E1", "target": "ejs@3.1.6", "type": "depends_on" },
    { "source": "ejs@3.1.6", "target": "CVE-2022-29078", "type": "vulnerable_to" },
    { "source": "CAP1", "target": "CVE-2022-29078", "type": "chains_to" }
  ],
  "attack_paths": [
    { "id": "P1", "nodes": ["E1","express","ejs@3.1.6","CVE-2022-29078","CAP2","A2"],
      "impact": "host RCE" }
  ],
  "summary": { "vulnerable_packages": 5, "attack_paths": 9,
    "fixes_needed": 2, "paths_eliminated": 8 }
}
```

### Vulnerabilities endpoint

**`GET /api/projects/{id}/vulns`** — Return all CVEs for a project, **ordered by connection count** (bridge centrality) descending — highest-priority first.

```json
[
  { "cve_id": "CVE-2022-29078", "package": "ejs", "version": "3.1.6",
    "cvss": 9.8, "epss": 0.71, "kev": false, "tier": "critical",
    "connections": 6, "fixed_version": "3.1.10",
    "description": "EJS template injection allows RCE via malicious locals.",
    "capabilities": ["template-injection", "RCE"],
    "chains_to": ["CVE-2021-23337"] },
  { "cve_id": "CVE-2021-23337", "package": "lodash", "version": "4.17.11",
    "cvss": 7.2, "epss": 0.43, "kev": false, "tier": "high",
    "connections": 4, "fixed_version": "4.17.21",
    "description": "Prototype pollution allows property injection.",
    "capabilities": ["prototype-pollution"],
    "chains_to": ["CVE-2022-29078"] }
]
```

Triage ordering rule: **`connections` (betweenness centrality) → `epss` → `kev` → `cvss`**. A node with 6 connections but CVSS 7 ranks above a node with 1 connection and CVSS 9.8 — this is the anti-flat-list insight.

### Plan of Action endpoint

**`POST /api/projects/{id}/plan`** — Generate a minimal, ordered remediation plan.

On call:
1. Fetches current vulnerability + graph state for the project
2. Queries OSV for each vulnerable package's `fixed` version range (`https://api.osv.dev/v1/query`)
3. Runs greedy set-cover: pick fixes that eliminate the most attack paths first
4. Sends the ordered fix set to **Claude Sonnet 4.6** to produce human-readable step descriptions
5. Returns the plan

```json
// Response
{
  "headline": "Fix 2 packages → 8 of 9 attack paths collapse.",
  "steps": [
    {
      "step": 1,
      "package": "ejs",
      "from": "3.1.6",
      "to": "3.1.10",
      "paths_broken": ["P1","P2","P3","P4","P5","P6"],
      "paths_broken_count": 6,
      "cves_closed": ["CVE-2022-29078"],
      "command": "npm install ejs@^3.1.10",
      "verify": "npm ls ejs",
      "osv_advisory": "https://osv.dev/vulnerability/GHSA-phwq-j96m-2c2q",
      "explanation": "This upgrade closes the EJS template injection, which is the entry point for 6 of your 9 attack paths including the full RCE chain."
    },
    {
      "step": 2,
      "package": "lodash",
      "from": "4.17.11",
      "to": "4.17.21",
      "paths_broken": ["P7","P8"],
      "paths_broken_count": 2,
      "cves_closed": ["CVE-2021-23337","CVE-2019-10744"],
      "command": "npm install lodash@^4.17.21",
      "verify": "npm ls lodash",
      "osv_advisory": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
      "explanation": "Closes prototype pollution. Without ejs already fixed, this would have been the gadget that turned template injection into RCE."
    }
  ],
  "residual": {
    "paths_remaining": 1,
    "description": "One low-severity path (CVSS 3.1, EPSS 0.02, no KEV) remains. No active exploits known.",
    "cves": ["CVE-2020-28500"]
  }
}
```

---

## 14. UX / User Flow

### Page map
```
/login  →  /dashboard  →  /projects/new  →  /projects/:id  (tab: Graph | Vulns | Triage | Plan)
```

### Auth — `/login`
- Single CTA: **"Sign in with GitHub"** (Better Auth GitHub OAuth).
- After OAuth callback, redirect to `/dashboard`.
- No email/password; GitHub is the only sign-in method for MVP.

### Dashboard — `/dashboard`
- Header: user avatar + GitHub login + sign-out button.
- **"New Project"** button → opens a modal (`Dialog`) to name the project and upload/paste a lockfile (any supported format; auto-detected).
- Project cards (shadcn `Card`) showing: project name, ecosystem badge, last-analyzed timestamp, summary stats (`X vulns · Y paths`), status badge (Pending / Analyzed).
- Clicking a project card → `/projects/:id`.

### Project detail — `/projects/:id`
- **Top banner:** project name, ecosystem, "Analyze" button.
- **"Analyze DB" button** → calls `POST /api/projects/{id}/analyze`.
  - While running: progress bar with states ("Fetching CVEs… Building graph… Running AI analysis…").
  - On complete: Claude Opus 4.8 narrative report surfaces in a collapsible card at the top.
- **Tab bar:** Graph · Vulnerabilities · Triage · Plan of Action.

#### Tab: Vulnerabilities — `/projects/:id?tab=vulns`
- Sortable table (shadcn `Table`) of all CVEs from `GET /api/projects/{id}/vulns`.
- **Default sort: `connections` descending** (most-connected nodes first = highest real-world priority).
- Columns: Package · Version · CVE ID · CVSS · EPSS · KEV badge · Connections · Tier badge · Fixed Version.
- Row click → slide-out `Sheet` drawer showing:
  - Full CVE description
  - Capabilities granted to attacker
  - Which other CVEs this chains to/from
  - Link to OSV advisory
- Callout banner for any node where CVSS is "Critical" but connections = 1: "⚠ High CVSS, low real-world priority — only 1 attack path routes through this."

#### Tab: Graph — `/projects/:id?tab=graph`
- Full-screen `react-force-graph-3d` canvas (Three.js/WebGL).
- 3D force-directed layout; Z = kill-chain depth.
- Node size = betweenness centrality (bridge score); color = triage tier.
- **Click any node** → right-side `Sheet` drawer with:
  - Node type and ID
  - For `cve` nodes: CVSS, EPSS, KEV, capabilities, fixed version, OSV link
  - For `dep` nodes: ecosystem, version, direct/transitive flag
  - For `capability` nodes: what the attacker can now do, which CVEs feed this
  - "Chains to" list (clickable, highlights the path in the graph)
- Click a `clean_cluster` node → expands inline to show real children.
- Side panel: attack path list; click a path → that path glows, everything else dims.

#### Tab: Triage — `/projects/:id?tab=triage`
- Priority-ordered list of CVE nodes, ranked by: connections → EPSS → KEV → CVSS.
- Tier badges (Critical / High / Medium / Low / Noise) derived from composite score, not raw CVSS.
- Each row shows the delta: "CVSS 9.8 → ranked #4 (only 1 path, no active exploit)".
- Expandable row → same detail as the Vulnerabilities drawer.

#### Tab: Plan of Action — `/projects/:id?tab=plan`
- **"Generate Plan"** button → calls `POST /api/projects/{id}/plan`.
- Headline: "Fix 2 packages → 8 of 9 attack paths collapse."
- Ordered step cards:
  - Step number, package name, version bump (from → to)
  - Paths broken count + CVEs closed
  - Claude-written plain-English explanation of why this step matters
  - Copy button for the exact terminal command
  - Link to OSV advisory
  - `npm ls <pkg>` verification command
- Residual risk section: what's left after all steps and why it's deprioritized.
- **"Simulate Fix"** toggle: animates glowing paths blinking out on the Graph tab as each step is applied.

---

## 15. Non-Functional Requirements
- **Performance:** graph render < 15s for typical projects; WebGL handles hundreds of nodes; demo seed kept to ~40–80 nodes for readability.
- **Reliability:** detection is deterministic; degrade gracefully if EPSS/KEV are slow (CVE list still renders).
- **Privacy:** lockfiles processed in-memory; nothing stored server-side by default. (Lockfiles contain no secrets — just package names/versions.)
- **Cost:** per-analysis LLM spend in cents; cache OSV/EPSS responses.
- **Honesty:** every node links to its public CVE source; non-goals stated in the UI footer.

---

## 16. Scope: MVP vs. Stretch

### MVP (must ship this weekend)
- ✅ GitHub OAuth sign-in via Better Auth.
- ✅ Dashboard with project history (SQLite-backed).
- ✅ Multi-ecosystem lockfile input: npm, PyPI, Go, Cargo, RubyGems — auto-detected.
- ✅ OSV detection + EPSS/KEV enrichment.
- ✅ Full tree build + clean-subtree collapse.
- ✅ **"Analyze DB" button** → Claude Opus 4.8 vulnerability report.
- ✅ **Vulnerabilities page** — sortable by connections (bridge centrality), not CVSS.
- ✅ **Graph page** — 3D force-directed; click node → detail drawer.
- ✅ **Triage tab** — composite priority ordering with CVSS-vs-reality callouts.
- ✅ **Plan of Action** — `POST /plan` → OSV fixed versions + greedy set-cover + Sonnet narration.
- ✅ "Fix K, break X/M" headline + fix-simulation animation.
- ✅ Figma dashboard design → implemented in React + shadcn/ui + Tailwind.
- ✅ Seed demo project that always renders a rich graph.

### Stretch (only if time allows)
- ⏩ File-permission and exposed-API-endpoint node layers.
- ⏩ Auto-generate a remediation PR.
- ⏩ `package.json` range resolution when no lockfile is provided.
- ⏩ Save/share a graph link.
- ⏩ PostgreSQL upgrade from SQLite.

---

## 17. Weekend Timeline

| When | Milestone |
|---|---|
| **Fri night — Step 1** | **Backend skeleton:** FastAPI app, Better Auth GitHub OAuth wired, SQLite DB, `POST /projects` + `GET /projects` working. Prove login → create project → list projects in browser. |
| **Fri night — Step 2** | **OSV ingest:** multi-ecosystem parser (npm first, others follow same interface). Lockfile → OSV batch query → list of real CVEs in console. **Prove data is real.** |
| **Sat AM — Step 3** | **Frontend scaffold:** React + Vite + Tailwind + shadcn/ui project created. Figma dashboard design finalized. Login page + Dashboard page built. |
| **Sat AM — Step 4** | **Analyze endpoint:** `POST /analyze` wired. Graph construction in networkx (nodes + CVSS-derived edges); EPSS/KEV enrichment. Claude Opus 4.8 narrative report returns. |
| **Sat PM — Step 5** | **LLM extraction:** Haiku 4.5 structured-output capability extraction → `enables`/`chains_to` edges. Triage scoring + connection-count ordering. |
| **Sat PM — Step 6** | **Vulnerabilities page:** `GET /vulns` endpoint + React table sorted by connections. Node detail drawer (Sheet). |
| **Sat night — Step 7** | **Graph page:** `react-force-graph-3d` renders full graph. Click-node drawer wired to node detail. Clean clusters collapsible. Attack path highlighting. |
| **Sun AM — Step 8** | **Plan of Action:** `POST /plan` endpoint (OSV fixed versions + greedy set-cover + Sonnet narration). Plan of Action tab in React with copy buttons + OSV links. |
| **Sun AM — Step 9** | **Triage tab:** Priority-ordered CVE list with composite scoring callouts. "This Critical is ranked #4" moments. |
| **Sun midday — Step 10** | **Polish:** fix-simulation animation, Figma → pixel-perfect pass, 3-min pitch rehearsal on seed repo. |

**De-risk:** seed a real vulnerable `package-lock.json` (old `ejs`, `lodash`, `minimist`, `node-fetch`, `ws`) so the demo always produces a rich graph. Test Saturday, not Sunday.

---

## 18. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Judge asks "is this real / hallucinated?" | Architecture makes it impossible — nodes come only from OSV; LLM draws edges, never nodes. Reproducible with `osv-scanner`. |
| LLM produces a wrong/implausible chain | LLM is constrained to confirmed CVEs + CVSS vectors; chains anchored in CVSS precondition/impact. Show CVSS basis in tooltips. |
| Graph looks like a flat line | Full-tree embedding + `chains_to` cross-links + 3D force-directed layout guarantee branching. |
| Auth complexity eats time | Better Auth does the heavy lifting; GitHub OAuth is its simplest provider. Budget 1–2 hours max. |
| Multi-ecosystem parser bugs | Start with npm (well-understood); other parsers follow the same interface. Normalize to `{name, version, ecosystem}` tuples; the rest of the pipeline is shared. |
| Opus 4.8 analyze call is slow | Run async; show progress states in UI. Cache the result in DB so re-opening the project is instant. |
| Live demo network failure (OSV down) | Cache OSV/EPSS responses for the seed project; ship offline fixtures. |
| shadcn/ui setup time | Use the CLI `npx shadcn@latest init` — installs all components in minutes. Figma design should be locked before writing React. |
| Large lockfile = unreadable graph | Clean-subtree collapse + capped demo seed (~40–80 nodes). |

---

## 19. Demo Script (3 Minutes)

1. **Customer (20s):** "Maya ships a Discord bot 1,200 people use. She got a security alert with 30 warnings. She doesn't understand them, so she ignored all of them. That's most solo maintainers."
2. **Problem (20s):** "Scanners show vulnerabilities in isolation, sorted by a score. The real danger is the *chain* — and nobody shows her that."
3. **Demo (90s):** Paste her `package-lock.json` → 3D graph appears → rotate it → "watch the attack flow from her public webhook down to her bot token." Click a path; it glows. Open triage: "This 'Critical' she panicked about? Low priority in her system." Hit **Simulate fix** → 2 upgrades → glowing paths blink out.
4. **Why it's real (20s):** "Every node is a confirmed CVE from public databases. The AI reasons about how they chain — it never invents a vulnerability."
5. **Survives the weekend (10s):** "Works on any public repo today, zero company access, all-free data. File permissions and exposed APIs are the next layers."

---

## 20. Future Roadmap (Beyond the Weekend)
- Additional ecosystems (PyPI, Maven, Go, Cargo).
- The non-dependency node layers: file permissions, exposed endpoints, default-credential IoT/config.
- One-click remediation PRs.
- CI integration (GitHub Action: post the attack-path graph + minimal fix set on every PR).
- "Watch this repo" — re-analyze on each new CVE and alert only when a *new attack path* opens (not on every new warning).

---

## 21. How This Scores Against the Judging Criteria
1. **Real value (highest weight):** turns an ignored wall of warnings into a 2-step fix for someone with no security skills — and shows the *minimal* action, not "fix everything."
2. **Customer fit:** built for reachable, real users (student/solo OSS maintainers); needs no privileged access; clear adoption reason.
3. **Innovation:** attack-path *chaining* + bridge-node minimal-fix triage + 3D visualization — not a clone of any existing flat-list scanner.
4. **Execution:** deterministic, verifiable data; a striking interactive 3D demo; a real seed repo.
5. **Pitch:** one undeniable moment — "fix 2, break 8 of 9 attack paths."

---

## 22. Open Questions
- Make the lockfile **required**, or add `package.json` range-resolution fallback? (Recommendation: required for MVP — cleanest and most accurate.)
- Auto-rotate the 3D graph by default, or start static with a "play" control?
- Show EPSS/KEV numerically in the UI, or abstract to "actively exploited" badges for non-technical users? (Recommendation: badges up front, numbers on hover.)
- Should the Plan of Action be generated automatically after Analyze, or stay as a separate button? (Recommendation: separate — keeps Analyze fast and lets users explore first.)
- Store project lockfiles in DB blob vs. filesystem? (Recommendation: DB blob for SQLite MVP, simplest deployment.)
- Should GitHub OAuth scope request `repo` access to auto-fetch lockfiles from the user's repos? (Recommendation: defer — user paste/upload is simpler and avoids OAuth scope complexity for MVP.)
