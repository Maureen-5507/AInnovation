
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import tldextract
from sklearn.ensemble import RandomForestClassifier

# ----------------------------
# 1. Flask & CORS Setup
# ----------------------------
app = Flask(__name__)
CORS(app)  # Allow all origins for development

# ----------------------------
# 2. Train Model (once at startup)
# ----------------------------
df = pd.read_csv("PhishingData.csv")
df.columns = df.columns.str.strip().str.lower()

X = df.drop(columns=["result"])
y = df["result"]

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# ----------------------------
# 3. Feature extraction function (from your code)
# ----------------------------
def extract_features(url):
    ext = tldextract.extract(url)
    return pd.DataFrame([{
        "index": 0,
        "having_iphaving_ip_address": int(any(char.isdigit() for char in ext.domain)),
        "urlurl_length": len(url),
        "shortining_service": int("bit.ly" in url or "tinyurl" in url),
        "having_at_symbol": int("@" in url),
        "double_slash_redirecting": int(url.count("//") > 1),
        "prefix_suffix": int("-" in ext.domain),
        "having_sub_domain": int(ext.subdomain.count('.') >= 1),
        "sslfinal_state": int("https" in url),
        "domain_registeration_length": 1,  # Placeholder
        "favicon": 1,                      # Placeholder
        "port": 0,                         # Placeholder
        "https_token": int("https" in ext.subdomain),
        "request_url": 1,                  # Placeholder
        "url_of_anchor": 1,                 # Placeholder
        "links_in_tags": 1,                 # Placeholder
        "sfh": 1,                           # Placeholder
        "submitting_to_email": int("mailto:" in url),
        "abnormal_url": 0,                  # Placeholder
        "redirect": int("->" in url),
        "on_mouseover": 0,                  # Placeholder
        "rightclick": 0,                    # Placeholder
        "popupwidnow": 0,                   # Placeholder
        "iframe": 0,                        # Placeholder
        "age_of_domain": 1,                 # Placeholder
        "dnsrecord": 1,                     # Placeholder
        "web_traffic": 1,                   # Placeholder
        "page_rank": 1,                     # Placeholder
        "google_index": 1,                  # Placeholder
        "links_pointing_to_page": 1,        # Placeholder
        "statistical_report": 0             # Placeholder
    }])

# ----------------------------
# 4. API Endpoint
# ----------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if "url" not in data:
            return jsonify({"error": "Missing 'url' in request"}), 400

        url = data["url"]
        features = extract_features(url)
        prob = model.predict_proba(features)[0]
        phishing_score = int(prob[1] * 100)  # Class 1 = phishing

        verdict = "SAFE" if phishing_score > 50 else "PHISHING"
        return jsonify({
            "url": url,
            "phishing_score": phishing_score,
            "verdict": verdict
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------------------
# 5. Health check route
# ----------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Backend is running"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
