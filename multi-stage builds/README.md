# Multi-Stage Docker Builds — Practical Use Case

> Demonstrating how multi-stage builds reduce container image size and attack surface using a real Node.js + TypeScript API.

---

## Repository Structure

```
multistagebuilds/
├── singlestage/          # Single-stage build — ships everything
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       └── index.ts
├── multistage/           # Multi-stage build — ships only what runs
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       └── index.ts
└── README.md             # This file
```

---

## The Problem statement

When building containerised Node.js applications, it is common to reach for a feature-rich dev image — one that has all the tools needed to compile, bundle, and test. The problem is that most teams then ship that same image to production, carrying along:

- Build tools (`esbuild`, `tsc`)
- Type definitions (`@types/node`, `@types/express`, `undici-types`)
- Raw TypeScript source files
- Test utilities and dev-only packages

None of these are needed at runtime. They inflate the image, increase the attack surface, and slow down deployments.

---

## The Solution — Multi-Stage Builds

Multi-stage builds let you use a rich dev image during the build phase and then copy only the compiled output into a lean runtime image. The builder layer is **never shipped**. Only the final runtime stage lands in your registry.

```
┌─────────────────────────────────┐       ┌──────────────────────────────┐
│  Stage 1 — builder              │       │  Stage 2 — runtime           │
│  cleanstart/node:latest-dev     │  ───► │  cleanstart/node:latest      │
│                                 │       │                              │
│  + npm install (all deps)       │       │  + dist/index.js only        │
│  + TypeScript source            │       │  + production deps only      │
│  + esbuild binary               │       │                              │
│  + tsconfig.json                │  ✗    │  ✗ no src/                   │
│                                 │       │  ✗ no esbuild                │
│  (discarded after build)        │       │  ✗ no @types/*               │
└─────────────────────────────────┘       └──────────────────────────────┘
```

---

## Real Metrics — From Actual Builds

> Numbers from `docker images` and `docker run ... du -sh /app/node_modules` on the same application.

| Metric | Single-stage | Multi-stage | Saving |
|---|---|---|---|
| **Image size** | 361 MB | 229 MB | ↓ 37% |
| **node_modules size** | 16.3 MB | 4.4 MB | ↓ 73% |
| **Image layers** | 14 | 13 | 1 stripped |
| **Runtime base image** | `latest-dev` | `latest` | lean runtime |
| **Build tools in prod** | yes | no | stripped |
| **TypeScript source in prod** | yes | no | stripped |

---

## Images Used

| Image | Purpose | Virtual Size |
|---|---|---|
| `cleanstart/node:latest-dev` | Builder — has all tools needed to compile | 295 MB |
| `cleanstart/node:latest` | Runtime — lean production image | 217 MB |

The `latest-dev` image is intentionally feature-rich for build-time use. The `latest` image is the lean counterpart meant for production. Multi-stage builds let you use both strategically.

---

## Quick Start

### Build and compare both images

```bash
# Build single-stage
cd singlestage
docker build -t singlestage .

# Build multi-stage
cd multistage
docker build -t multistage .

# Compare sizes
docker images | grep -E "singlestage|multistage"

# Inspect what's inside each image
docker run --rm --entrypoint="" singlestage:latest sh -c "find /app -type f | head -40"
docker run --rm --entrypoint="" multistage:latest sh -c "find /app -type f"

# Compare node_modules size
docker run --rm --entrypoint="" singlestage:latest sh -c "du -sh /app/node_modules"
docker run --rm --entrypoint="" multistage:latest sh -c "du -sh /app/node_modules"
```

### Run the API

```bash
# Single-stage
docker run -p 3000:3000 singlestage

# Multi-stage
docker run -p 3001:3000 multistage

# Test
curl http://localhost:3000
curl http://localhost:3001
```

---

## Why This Matters in Production

### Reduced attack surface
Every file that ships to production is a potential exploit path. Build tools, TypeScript sources, and type definitions in a running container serve no purpose — they only add risk. Multi-stage builds strip them out by design, not by convention.

### Smaller node_modules
The single-stage image ships 16.3 MB of `node_modules` — including `esbuild`, `@types/node`, `undici-types`, and all devDependencies. The multi-stage runtime runs `npm install --omit=dev`, bringing that down to 4.4 MB of only what Express actually needs.

### Faster deployments
132 MB less per image pull. Across multiple pods, rolling deployments, and multi-region setups, that difference compounds into real seconds saved per deploy cycle and measurable bandwidth cost reductions.

### Enforced discipline
Multi-stage builds make the separation between build-time and runtime a hard boundary in the Dockerfile itself. It is no longer a convention that someone might accidentally break — the runtime stage simply cannot access anything that was not explicitly copied from the builder.

---

## Detailed Documentation

- [singlestage/README.md](./singlestage/README.md) — Single-stage build explained
- [multistage/README.md](./multistage/README.md) — Multi-stage build explained

---

## Tech Stack

- **Runtime**: Node.js v25.8.1
- **Framework**: Express 4.x
- **Language**: TypeScript (compiled via esbuild)
- **Base images**: `cleanstart/node:latest-dev`, `cleanstart/node:latest`
- **Build tool**: esbuild