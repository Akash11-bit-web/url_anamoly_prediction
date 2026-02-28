import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from model import extract_features
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from model import extract_features  # now this will work
# Sample dataset — replace with a real dataset for production
sample_urls = [
    ("https://www.google.com", 1),
    ("https://www.github.com", 1),
    ("https://www.amazon.com/shop", 1),
    ("http://192.168.1.1/login/verify", 0),
    ("http://free-click-here.com/update/bank", 0),
    ("http://secure-login.verify-account.com", 0),
    ("https://www.stackoverflow.com", 1),
    ("http://phishing-site.ru/login", 0),
    ("https://docs.python.org/3/", 1),
    ("http://malicious.xyz/confirm/account", 0),
]

X = [extract_features(url) for url, label in sample_urls]
y = [label for url, label in sample_urls]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print(classification_report(y_test, model.predict(X_test)))

joblib.dump(model, "rf_model.pkl")
print("✅ Model saved as rf_model.pkl")