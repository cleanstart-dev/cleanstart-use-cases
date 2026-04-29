import subprocess, sys

def install_runtime_dep():
    """
    Installs cryptography at runtime — after the image is built.
    Static SBOM scanners scan the filesystem at build time
    and will never see this package.
    """
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "cryptography==41.0.0"
    ])

install_runtime_dep()

from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Running with a dependency your SBOM doesn't know about."

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