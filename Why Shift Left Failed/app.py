from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Running."

@app.route("/health")
def health():
    return {"status": "ok"}, 200

if __name__ == "__main__":
    import os
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 5000)),
        debug=os.getenv("DEBUG", "false").lower() == "true"
    )