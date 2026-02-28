import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from model import extract_features, analyze_suspicious_reasons
from domain_info import get_domain_info

app = FastAPI(title="URL Anomaly Detection API")
rf_model = joblib.load("rf_model.pkl")

class URLRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"message": "URL Anomaly Detection API is running"}

@app.post("/predict")
def predict(request: URLRequest):
    features = extract_features(request.url)
    prediction = rf_model.predict([features])[0]
    probability = rf_model.predict_proba([features])[0]
    label = "✅ Legitimate" if prediction == 1 else "🚨 Phishing / Malicious"
    confidence = round(max(probability) * 100, 2)

    result = {
        "url": request.url,
        "prediction": int(prediction),
        "label": label,
        "confidence": f"{confidence}%",
    }

    # If not legitimate — add suspicious analysis
    if prediction == 0:
        analysis = analyze_suspicious_reasons(request.url)
        result["reasons"] = analysis["reasons"]
        result["attack_types"] = analysis["attack_types"]
        result["risk_level"] = analysis["risk_level"]

    return result

@app.post("/domain-info")
def domain_info(request: URLRequest):
    info = get_domain_info(request.url)
    return info