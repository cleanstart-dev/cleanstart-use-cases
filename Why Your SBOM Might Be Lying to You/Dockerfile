# Use the cleanstart python base image
FROM cleanstart/python:latest-dev

WORKDIR /app

USER root

RUN apk update && apk search pip

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app

RUN python -m venv /venv && \
    chown -R appuser:appuser /venv

ENV PATH="/venv/bin:$PATH"

# Only flask and requests are declared here — visible to SBOM scanners ✓
# cryptography is missing intentionally to demonstrate the gap ✗
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app/data

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

ENV DATABASE_PATH=/app/data/users.db
ENV DEBUG=false
ENV HOST=0.0.0.0
ENV PORT=5000

ENTRYPOINT ["python"]
CMD ["app.py"]