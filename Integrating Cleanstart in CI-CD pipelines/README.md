# Using Cleanstart Images in CI/CD Pipelines

Cleanstart provides two categories of images for different stages of a pipeline: **dev images** and **prod images**. Knowing which to use and when is key to keeping pipelines both functional and secure.


## Dev Images — For Pipeline Stages

Dev images include a shell (`/bin/sh`), standard Unix utilities, and package managers. This makes them suitable for pipeline steps that need to **run commands**, install tools, execute tests, or inspect the environment.

### When to use a dev image

- Running test suites
- Linting and static analysis
- Building artifacts (compiling, bundling)
- Any step that uses shell scripting or chained commands

### Example — Running tests in a pipeline

```yaml
# cloudbuild.yaml
steps:
  - name: cleanstart/python:latest-dev
    entrypoint: sh
    args:
      - -c
      - |
        python -m venv /tmp/venv
        /tmp/venv/bin/pip install -r requirements.txt
        pytest tests/ -v
```

The dev image gives you `/bin/sh`, so you can chain commands with `&&`, use pipes, run scripts, and install dependencies during the pipeline run — none of this ends up in the final image.

### Example — Linting step

```yaml
  - name: cleanstart/python:latest-dev
    entrypoint: sh
    args:
      - -c
      - python -m venv /tmp/venv
        /tmp/venv/bin/pip install flake8 && flake8 app.py
```

> **Key point:** Dev images are ephemeral in a pipeline — they execute and discard. Their larger surface area (shell, tools) is acceptable here because nothing they contain ships to production.


## Prod Images — For Building and Running

Prod images (`cleanstart/python:latest`) are hardened. They have **no shell**, no Unix utilities, and run as a non-root user (UID 65532). This makes them unsuitable for pipeline command steps but ideal as the base for any image that will actually run in production.

### What this means for your Dockerfile

Because there is no shell or `chown`/`chmod` available:

- All `RUN` instructions must use **exec form** `["binary", "arg"]` — not shell form
- File ownership must be set via `COPY --chown` at copy time, not via a `RUN chown`
- Any setup requiring shell scripting must happen in a prior pipeline stage using a dev image, not inside the Dockerfile

### Example — Production Dockerfile (this repo)

```dockerfile
FROM cleanstart/python:latest

WORKDIR /app

USER root

# Exec form — no shell available
RUN ["python", "-m", "venv", "/venv"]

ENV PATH="/venv/bin:$PATH"

# --chown handles ownership natively, no chown binary needed
COPY --chown=65532:65532 requirements.txt .
RUN ["pip", "install", "--no-cache-dir", "-r", "requirements.txt"]

COPY --chown=65532:65532 app.py .

# Drop to non-root before runtime
USER 65532

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5050/health')"]

ENV DEBUG=false
ENV HOST=0.0.0.0
ENV PORT=5050

ENTRYPOINT ["/usr/bin/python"]
CMD ["app.py"]
```

### Example — Full pipeline: test with dev, build with prod

```yaml
# cloudbuild.yaml
steps:
  # Stage 1: Use dev image to run tests
  - name: cleanstart/python:dev
    id: test
    entrypoint: /bin/sh
    args:
      - -c
      - pip install -r requirements.txt && pytest tests/ -v

  # Stage 2: Use prod image as base to build the final image
  - name: gcr.io/cloud-builders/docker
    id: build
    args:
      - build
      - -t
      - us-central1-docker.pkg.dev/$PROJECT_ID/my-repo/my-app:$COMMIT_SHA
      - .
    waitFor: [test]

  # Stage 3: Push the final image
  - name: gcr.io/cloud-builders/docker
    id: push
    args:
      - push
      - us-central1-docker.pkg.dev/$PROJECT_ID/my-repo/my-app:$COMMIT_SHA
    waitFor: [build]
```

> **Key point:** The prod image never runs commands during the pipeline — it is only used as the `FROM` base inside the Dockerfile. The Docker builder (`gcr.io/cloud-builders/docker`) is what builds it.


## Quick Reference

| | Dev Image | Prod Image |
|---|---|---|
| Has `/bin/sh` | Yes | No |
| Has Unix utilities | Yes | No |
| Runs as root | Configurable | No (UID 65532) |
| Use in pipeline steps | Yes | No |
| Use as Dockerfile base | No | Yes |
| Ships to production | No | Yes |
| `RUN` form | Shell or exec | Exec only |
| File ownership | `chown` or `COPY --chown` | `COPY --chown` only |


## Common Mistakes

**Using shell-form RUN with a prod base image**
```dockerfile
# Fails — no /bin/sh
RUN pip install -r requirements.txt

# Correct
RUN ["pip", "install", "-r", "requirements.txt"]
```

**Using chown inside a prod-based Dockerfile**
```dockerfile
# Fails — no /bin/chown
RUN chown -R clnstrt:clngroup /app

# Correct
COPY --chown=65532:65532 app.py .
```

**Running tests inside the prod Dockerfile**
```dockerfile
# Wrong — installs test deps into production image
RUN ["pip", "install", "pytest"]
RUN ["pytest", "tests/"]
```
Run tests in a separate pipeline step using the dev image instead.
