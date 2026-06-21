import pandas as pd
import re
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ---------------------------
# Improved Feature Extraction
# ---------------------------
def extract_features(url):
    features = {}
    url = str(url).strip().lower()

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    # Basic URL features
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

    # Presence based features
    features['has_at'] = 1 if '@' in url else 0
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_http_only'] = 1 if url.startswith('http://') else 0
    # features['has_www'] = 1 if 'www.' in domain else 0

    # IP address check
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0

    # Shortened URL services
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
        'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'rebrand.ly'
    ]
    features['is_shortened'] = 1 if any(short in url for short in shorteners) else 0

    # Suspicious words
    suspicious_words = [
        'login', 'verify', 'update', 'bank', 'secure', 'account',
        'signin', 'confirm', 'password', 'ebayisapi', 'webscr',
        'wallet', 'billing', 'recover', 'support'
    ]
    features['suspicious_words_count'] = sum(word in url for word in suspicious_words)

    # Suspicious brand words often abused in phishing
    brand_words = ['paypal', 'bank', 'signin', 'secure', 'account', 'billing', 'wallet']
    features['has_brand_word'] = 1 if any(word in url for word in brand_words) else 0

    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
    features['has_suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
    # Query parameter count
    features['num_params'] = query.count('&') + 1 if query else 0

    # Too many special characters
    special_chars = ['@', '-', '?', '=', '&', '%', '_']
    features['special_char_count'] = sum(url.count(ch) for ch in special_chars)

    return features

# ---------------------------
# Load dataset
# ---------------------------
df = pd.read_csv("../dataset/malicious_phish.csv")

print("Dataset loaded successfully!")
print(df.head())
print("\nColumns:", df.columns)

# Keep only required columns
df = df[['url', 'type']].dropna()

# Binary mapping:
# benign = 0
# phishing/defacement/malware = 1
df['label'] = df['type'].apply(lambda x: 0 if str(x).lower() == 'benign' else 1)

print("\nClass distribution:")
print(df['type'].value_counts())

# ---------------------------
# Extract improved features
# ---------------------------
feature_list = [extract_features(url) for url in df['url']]
X = pd.DataFrame(feature_list)
y = df['label']

print("\nExtracted Features:")
print(X.head())

# ---------------------------
# Split dataset
# ---------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ---------------------------
# Train improved model
# ---------------------------
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ---------------------------
# Predict and Evaluate
# ---------------------------
y_pred = model.predict(X_test)

print("\nModel Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ---------------------------
# Save model
# ---------------------------
joblib.dump(model, "../model/phishing_model.pkl")
print("\nImproved model saved successfully as phishing_model.pkl")