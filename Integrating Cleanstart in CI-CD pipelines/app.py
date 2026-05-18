import os
from flask import Flask, jsonify

app = Flask(__name__)

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 5050))
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "python-app"}), 200


@app.route("/")
def home():
    return jsonify({"message": "Hello from CleanStart!"}), 200


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)