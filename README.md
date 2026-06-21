# Phishing Website Detection Using Machine Learning

## Overview
This project is a phishing website detection system that classifies a website URL as **Legitimate** or **Malicious/Phishing** using Machine Learning.  
It uses URL-based feature extraction and a trained classification model to detect suspicious URLs.  
A simple GUI is also included to make URL checking user-friendly.

## Features
- Detects whether a website URL is legitimate or phishing
- Uses Machine Learning for URL classification
- Extracts multiple URL-based security features
- Includes trusted domain validation to reduce false positives
- Provides a simple GUI interface for easy testing

## Technologies Used
- Python
- Pandas
- NumPy
- Scikit-learn
- Joblib
- Tkinter

## Project Structure
phishing-website-detection-ml/
│
├── dataset/
│ └── malicious_phish.csv
│
├── model/
│ └── phishing_model.pkl
│
├── src/
│ ├── train_model.py
│ ├── predict.py
│ └── gui_app.py
│
├── requirements.txt
└── README.md

## How It Works
1. Load malicious and legitimate URL dataset
2. Extract URL-based features such as:
   - URL length
   - Domain length
   - Number of dots
   - Number of digits
   - Number of subdomains
   - Suspicious words in URL
   - Presence of HTTPS
   - Special characters and suspicious TLDs
3. Train a Machine Learning model on the extracted features
4. Save the trained model
5. Predict whether a new URL is legitimate or malicious
6. Use GUI to check URLs easily

## Example Test URLs
### Legitimate
- https://www.google.com
- https://github.com

### Suspicious / Phishing-like
- http://paypal-login-secure-update.xyz
- http://secure-login-bank-update.com

## Output Example
- BENIGN / LEGITIMATE URL
- MALICIOUS / PHISHING URL

- ## Screenshots

### Legitimate URL Detection
![Benign URL Test]
<img width="1920" height="1080" alt="imagesbenign-test png" src="https://github.com/user-attachments/assets/eb442846-6d0b-4fbf-8a5d-3e0dce032d09" />


### Malicious URL Detection
![Malicious URL Test]
<img width="1920" height="1080" alt="imagesmalicious-test png" src="https://github.com/user-attachments/assets/f73e5f1c-95b8-4ac8-94aa-dc11b382ac70" />


## Future Improvements
- Use live URL reputation APIs
- Add website content-based phishing detection
- Deploy as a web app using Flask or Streamlit
- Improve model with more advanced feature engineering

## Author
**Sai Praneetha Vukanti**
Aspiring SOC Analyst | Cybersecurity Enthusiast | CSE Undergraduate
