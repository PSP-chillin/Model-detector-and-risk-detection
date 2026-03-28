"""
Example insecure Flask API that serves a trained ML model.
This file intentionally contains several security vulnerabilities.
DO NOT use in production.
"""
import pickle
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# ── Vulnerability: CORS wildcard ─────────────────────────────────────────────
CORS(app, allow_origins=["*"])

# ── Vulnerability: hardcoded secret key ──────────────────────────────────────
app.config["SECRET_KEY"] = "hunter2"

# Load model unsafely at startup
with open("model.pkl", "rb") as f:
    MODEL = pickle.load(f)      # HIGH: unsafe deserialization


# ── Vulnerability: unauthenticated POST endpoint ─────────────────────────────
@app.route("/predict", methods=["POST"])
def predict():
    """Accepts raw JSON input and returns model prediction – no auth."""
    data = request.get_json()
    # ── Vulnerability: eval on user input ────────────────────────────────────
    features = eval(data.get("features", "[]"))   # HIGH
    prediction = MODEL.predict([features])
    return jsonify({"prediction": prediction.tolist()})


# ── Vulnerability: debug mode in production ───────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")   # HIGH  # noqa: S201 (intentional – demo only)
