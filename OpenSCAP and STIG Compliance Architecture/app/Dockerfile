# ─────────────────────────────────────────────────────────────────
# Stage 1: Build — create a virtual env in the user's home directory.
# The base image is PEP 668-managed (Python 3.14 on Alpine), so we
# must use a venv rather than installing into the system Python.
# Placing the venv in /home/clnstrt avoids the permission issues
# we'd hit with /opt/venv (the non-root build user can't write to /opt).
# ─────────────────────────────────────────────────────────────────
FROM cleanstart/python:latest-dev AS builder

COPY requirements.txt /tmp/requirements.txt

# Create the venv (ensurepip bootstraps pip inside it automatically)
# then install dependencies
RUN python -m venv /home/clnstrt/venv && \
    /home/clnstrt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /home/clnstrt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# ─────────────────────────────────────────────────────────────────
# Stage 2: Runtime — distroless cleanstart/python:latest
# ─────────────────────────────────────────────────────────────────
FROM cleanstart/python:latest

WORKDIR /app

# Copy the entire venv from the builder
COPY --from=builder /home/clnstrt/venv /home/clnstrt/venv
COPY app.py .

# Activate the venv by putting its bin/ first on PATH
ENV PATH="/home/clnstrt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

ENTRYPOINT ["python", "app.py"]