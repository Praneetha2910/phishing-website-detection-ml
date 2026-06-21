import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# Load trained model
model = joblib.load("../model/phishing_model.pkl")

# Trusted safe domains
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "github.com", "microsoft.com",
    "amazon.com", "amazon.in", "wikipedia.org", "openai.com",
    "linkedin.com", "facebook.com", "instagram.com", "twitter.com", "x.com"
]

def is_trusted_domain(url):
    url = str(url).strip().lower()
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False

def extract_features(url):
    features = {}
    url = str(url).strip().lower()

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_underscores'] = url.count('_')
    features['num_questionmarks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    features['num_percent'] = url.count('%')
    features['num_subdomains'] = domain.count('.')

    features['has_at'] = 1 if '@' in url else 0
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_http_only'] = 1 if url.startswith('http://') else 0

    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0

    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
        'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'rebrand.ly'
    ]
    features['is_shortened'] = 1 if any(short in url for short in shorteners) else 0

    suspicious_words = [
        'login', 'verify', 'update', 'bank', 'secure', 'account',
        'signin', 'confirm', 'password', 'ebayisapi', 'webscr',
        'wallet', 'billing', 'recover', 'support'
    ]
    features['suspicious_words_count'] = sum(word in url for word in suspicious_words)

    brand_words = ['paypal', 'bank', 'signin', 'secure', 'account', 'billing', 'wallet']
    features['has_brand_word'] = 1 if any(word in url for word in brand_words) else 0

    suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
    features['has_suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0

    features['num_params'] = query.count('&') + 1 if query else 0

    special_chars = ['@', '-', '?', '=', '&', '%', '_']
    features['special_char_count'] = sum(url.count(ch) for ch in special_chars)

    return pd.DataFrame([features])

# Prediction
test_url = input("Enter URL to check: ").strip()

# Step 1: trusted domain check
if is_trusted_domain(test_url):
    print("✅ This URL is BENIGN / LEGITIMATE (Trusted Domain)")
else:
    # Step 2: ML prediction
    features = extract_features(test_url)
    prediction = model.predict(features)[0]

    if prediction == 1:
        print("⚠️ This URL is MALICIOUS / PHISHING")
    else:
        print("✅ This URL is BENIGN / LEGITIMATE")