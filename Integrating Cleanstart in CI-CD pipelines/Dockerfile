FROM cleanstart/python:latest

WORKDIR /app

USER root

RUN ["python", "-m", "venv", "/venv"]

ENV PATH="/venv/bin:$PATH"

COPY --chown=65532:65532 requirements.txt .
RUN ["pip", "install", "--no-cache-dir", "-r", "requirements.txt"]

COPY --chown=65532:65532 app.py .

USER 65532

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5050/health')"]

ENV DEBUG=false
ENV HOST=0.0.0.0
ENV PORT=5050

ENTRYPOINT ["/usr/bin/python"]
CMD ["app.py"]