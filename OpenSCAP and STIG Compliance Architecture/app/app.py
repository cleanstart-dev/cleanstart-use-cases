"""
Minimal Flask app to demonstrate running a real workload
on top of cleanstart/python:latest.
"""
from flask import Flask, jsonify
import os
import sys

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify({
        "message": "Hello from a STIG-hardened container!",
        "base_image": "cleanstart/python:latest",
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/whoami")
def whoami():
    """Demonstrates the container is running as a non-root user."""
    return jsonify({
        "uid": os.getuid(),
        "gid": os.getgid(),
        "is_root": os.getuid() == 0,
        "python_version": sys.version,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
