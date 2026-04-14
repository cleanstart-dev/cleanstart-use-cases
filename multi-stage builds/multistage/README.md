# Multi-Stage Build

This folder contains the **multi-stage** Docker build of the same Node.js + TypeScript Express API. It demonstrates how to use a rich dev image freely during the build phase while shipping only the compiled output in a lean runtime image.

---

## Folder Structure

```
multistage/
├── Dockerfile
├── package.json
├── tsconfig.json
└── src/
    └── index.ts
```

---

## Dockerfile

```dockerfile
FROM cleanstart/node:latest-dev AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY src/ ./src/
COPY tsconfig.json .
RUN npm run build

FROM cleanstart/node:latest AS runtime
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json .
RUN npm install --omit=dev
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

---

## How It Works

### Stage 1 — builder

```dockerfile
FROM cleanstart/node:latest-dev AS builder
```

- Uses the full `cleanstart/node:latest-dev` image (295 MB).
- Installs all dependencies including devDependencies (`esbuild`, `@types/*`).
- Compiles TypeScript source to `dist/index.js`.
- **This stage is never shipped.** It exists only to produce the build artifacts.

### Stage 2 — runtime

```dockerfile
FROM cleanstart/node:latest AS runtime
```

- Starts completely fresh from `cleanstart/node:latest` (217 MB) — the lean production image.
- Uses `COPY --from=builder` to selectively pull only `dist/` and `package*.json` from the builder stage.
- Runs `npm install --omit=dev` to install only production dependencies.
- Everything from Stage 1 — esbuild, TypeScript source, type definitions, tsconfig — is **automatically discarded**.

---

## What Gets Shipped vs Discarded

```
Builder stage (discarded)          Runtime stage (shipped)
──────────────────────────         ────────────────────────
src/index.ts              ✗        dist/index.js         ✓
tsconfig.json             ✗        package.json          ✓
esbuild binary            ✗        express + deps        ✓
@types/node               ✗
undici-types              ✗
All devDependencies       ✗
```

Running `find /app -type f` inside the multistage container shows only:

```
/app/dist/index.js
/app/package.json
/app/package-lock.json
/app/node_modules/express/...
/app/node_modules/...   (production deps only)
```

---

## Metrics

| Metric | Value |
|---|---|
| **Image size** | 229 MB |
| **node_modules** | 4.4 MB |
| **Image layers** | 13 |
| **Base image** | `cleanstart/node:latest` |
| **Build tools in image** | no — esbuild stays in builder |
| **TypeScript source in image** | no — only `dist/` ships |
| **devDependencies in image** | no — `--omit=dev` enforced |

---

## Build and Run

```bash
# Build
docker build -t multistage .

# Check image size
docker images multistage

# Inspect contents — notice how clean this is vs singlestage
docker run --rm --entrypoint="" multistage:latest sh -c "find /app -type f"

# Check node_modules size
docker run --rm --entrypoint="" multistage:latest sh -c "du -sh /app/node_modules"

# Run the API
docker run -p 3000:3000 multistage

# Test
curl http://localhost:3000
```

---

## Before vs After Comparison

| Metric | Single-stage | Multi-stage | Saving |
|---|---|---|---|
| Image size | 361 MB | **229 MB** | ↓ 37% |
| node_modules | 16.3 MB | **4.4 MB** | ↓ 73% |
| Image layers | 14 | **13** | 1 stripped |
| Runtime base | `latest-dev` | **`latest`** | lean image |
| Build tools in prod | yes | **no** | stripped |
| TypeScript source in prod | yes | **no** | stripped |

---

## Key Benefits

### Reduced attack surface
The esbuild binary, raw TypeScript source files, and type definition packages never reach the production container. Fewer binaries and files mean fewer potential exploit paths if the container is compromised.

### 73% smaller node_modules
`npm install --omit=dev` in the runtime stage installs only what Express needs to run — not what esbuild needed to compile. The result is 4.4 MB instead of 16.3 MB.

### Leaner base image
The runtime stage starts from `cleanstart/node:latest` (217 MB) instead of `cleanstart/node:latest-dev` (295 MB). Combined with stripped dev packages, the final image is 132 MB smaller.

### Hard boundary between build and runtime
The separation is enforced by the Dockerfile structure itself. There is no way for dev tooling to accidentally slip into the runtime stage — it is structurally impossible unless explicitly copied with `COPY --from=builder`.

---

## The Pattern in One Line

> Use the dev image to build. Use the prod image to run. Let Docker discard everything in between.

---

## Related

- [singlestage/README.md](../singlestage/README.md) — The anti-pattern this improves on
- [Main README](../README.md) — Full project overview and comparison