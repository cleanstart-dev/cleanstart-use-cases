# Single-Stage Build

This folder contains the **single-stage** Docker build of a Node.js + TypeScript Express API. It represents the common anti-pattern where a developer uses a full dev image and ships it directly to production without any separation between build-time and runtime.

---

## Folder Structure

```
singlestage/
├── Dockerfile
├── package.json
├── tsconfig.json
└── src/
    └── index.ts
```

---

## Dockerfile

```dockerfile
FROM cleanstart/node:latest-dev
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY src/ ./src/
COPY tsconfig.json .
RUN npm run build
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### What happens here

1. The full dev image `cleanstart/node:latest-dev` (295 MB) is used as the base.
2. All dependencies — including devDependencies like `esbuild` and `@types/*` — are installed via `npm install`.
3. TypeScript source is compiled to `dist/index.js` using esbuild.
4. The entire context — dev image, dev packages, source files, build config — is baked into the final image.

---

## The Problem

### Everything ships to production

Running `find /app -type f` inside the container reveals exactly what gets shipped:

```
/app/dist/index.js          ← needed
/app/src/index.ts           ← NOT needed in prod
/app/tsconfig.json          ← NOT needed in prod
/app/node_modules/esbuild/  ← NOT needed in prod (build tool)
/app/node_modules/@types/   ← NOT needed in prod (type defs)
/app/node_modules/undici-types/ ← NOT needed in prod
/app/package.json
/app/package-lock.json
```

### Metrics

| Metric | Value |
|---|---|
| **Image size** | 361 MB |
| **node_modules** | 16.3 MB |
| **Image layers** | 14 |
| **Base image** | `cleanstart/node:latest-dev` |
| **Build tools in image** | yes — esbuild binary present |
| **TypeScript source in image** | yes — `src/index.ts` ships to prod |
| **devDependencies in image** | yes — @types/*, undici-types, etc. |

---

## Build and Run

```bash
# Build
docker build -t singlestage .

# Check image size
docker images singlestage

# Inspect contents
docker run --rm --entrypoint="" singlestage:latest sh -c "find /app -type f"

# Check node_modules size
docker run --rm --entrypoint="" singlestage:latest sh -c "du -sh /app/node_modules"

# Run the API
docker run -p 3000:3000 singlestage

# Test
curl http://localhost:3000
```

---

## Why This Is a Problem in Production

### Attack surface
The `esbuild` binary, raw TypeScript source, and type definition packages all ship inside the running container. If the container is ever compromised, an attacker has access to more binaries and source code than necessary.

### Bloat
16.3 MB of `node_modules` includes packages that are only needed at build time. In production, only Express and its runtime dependencies are needed — not `esbuild`, `@types/node`, or `undici-types`.

### No separation of concerns
There is no boundary between what was needed to build the app and what is needed to run it. These are fundamentally different requirements but this Dockerfile treats them as the same.

---

## Comparison

See the [multi-stage build](../multistage/README.md) to see how these problems are solved, and the [main README](../README.md) for a full side-by-side comparison.