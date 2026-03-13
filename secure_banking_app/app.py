"""
Flask Backend for Secure Banking Application
Handles authentication, session management, risk scoring, and honeypot activation.
ALL SECURITY LOGIC IS IN THE BACKEND.
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import os
import joblib
import json
import pandas as pd
from datetime import datetime, timedelta
import hashlib
import secrets
from werkzeug.security import check_password_hash, generate_password_hash
from honeypot import get_honeypot_data

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

MODEL_PATH = 'models/risk_model.pkl'
SCALER_PATH = 'models/scaler.pkl'
FEATURE_INFO_PATH = 'models/feature_info.json'

model = None
scaler = None
feature_names = None


def load_model():
    """Load trained ML model"""
    global model, scaler, feature_names

    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)

        with open(FEATURE_INFO_PATH, 'r') as f:
            feature_info = json.load(f)
            feature_names = feature_info['features']

        print("✓ Model loaded successfully")
        return True
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return False


# -------------------------------------------------
# RISK SCORING FUNCTION (THIS WAS MISSING)
# -------------------------------------------------

def calculate_risk_score(features):
    """
    Calculate risk score using ML model if available,
    otherwise fallback to rule-based scoring.
    """

    try:

        # If ML model exists
        if model and scaler and feature_names:

            feature_values = [features[f] for f in feature_names]
            df = pd.DataFrame([feature_values], columns=feature_names)

            scaled = scaler.transform(df)

            prediction = model.predict(scaled)[0]

            if prediction == -1:
                risk_score = 80
                risk_level = "high"
            else:
                risk_score = 20
                risk_level = "low"

            return risk_score, risk_level

    except Exception as e:
        print("ML scoring failed, using fallback:", e)

    # -------------------------
    # Fallback rule-based risk
    # -------------------------

    risk_score = 0

    if features['login_attempts'] > 3:
        risk_score += 30

    if features['request_rate'] > 20:
        risk_score += 25

    if features['ip_changed'] == 1:
        risk_score += 20

    if features['device_changed'] == 1:
        risk_score += 15

    if features['transaction_amount'] > 10000:
        risk_score += 20

    if features['hour_of_day'] < 6 or features['hour_of_day'] > 22:
        risk_score += 10

    risk_score = min(risk_score, 100)

    if risk_score < 30:
        risk_level = "low"
    elif risk_score < 70:
        risk_level = "medium"
    else:
        risk_level = "high"

    return risk_score, risk_level


# -------------------------------------------------
# DEMO USERS
# -------------------------------------------------

DEMO_USERS = {
    'customer001': {
        'password_hash': generate_password_hash('SecurePass123!'),
        'name': 'Alice Johnson',
        'account_number': '1234-5678',
        'account_type': 'Checking',
        'balance': 12450.75,
        'available_balance': 12450.75
    },
    'customer002': {
        'password_hash': generate_password_hash('BankDemo456!'),
        'name': 'Bob Martinez',
        'account_number': '8765-4321',
        'account_type': 'Savings',
        'balance': 25300.50,
        'available_balance': 25300.50
    }
}

# -------------------------------------------------
# REAL TRANSACTIONS
# -------------------------------------------------

REAL_TRANSACTIONS = {
    'customer001': [
        {'date': '2026-02-04', 'description': 'Salary Deposit',
            'amount': 4500.00, 'type': 'Credit', 'status': 'Completed'},
        {'date': '2026-02-03', 'description': 'Whole Foods',
            'amount': -125.43, 'type': 'Debit', 'status': 'Completed'},
        {'date': '2026-02-02', 'description': 'Shell Gas Station',
            'amount': -65.20, 'type': 'Debit', 'status': 'Completed'},
    ],
    'customer002': [
        {'date': '2026-02-04', 'description': 'Transfer from Checking',
            'amount': 1000.00, 'type': 'Transfer', 'status': 'Completed'},
    ]
}

# -------------------------------------------------
# SESSION TRACKING
# -------------------------------------------------

session_data = {}


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'


def get_device_fingerprint():
    user_agent = request.headers.get('User-Agent', '')
    return hashlib.md5(user_agent.encode()).hexdigest()[:16]


def extract_session_features(customer_id):

    session_id = session.get('session_id')

    if session_id not in session_data:

        session_data[session_id] = {
            'login_attempts': session.get('login_attempts', 1),
            'request_count': 0,
            'start_time': datetime.now(),
            'initial_ip': get_client_ip(),
            'initial_device': get_device_fingerprint()
        }

    data = session_data[session_id]
    data['request_count'] += 1

    current_time = datetime.now()

    session_duration = (current_time - data['start_time']).total_seconds() / 60

    request_rate = data['request_count'] / max(session_duration, 0.1)

    ip_changed = 1 if get_client_ip() != data['initial_ip'] else 0
    device_changed = 1 if get_device_fingerprint(
    ) != data['initial_device'] else 0

    transaction_amount = session.get('last_transaction_amount', 100)

    hour_of_day = current_time.hour
    day_of_week = current_time.weekday()

    return {
        'login_attempts': data['login_attempts'],
        'request_rate': round(request_rate, 2),
        'ip_changed': ip_changed,
        'device_changed': device_changed,
        'transaction_amount': transaction_amount,
        'session_duration': round(session_duration, 2),
        'hour_of_day': hour_of_day,
        'day_of_week': day_of_week
    }


# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route('/')
def index():
    if 'customer_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():

    customer_id = request.form.get('customer_id')
    password = request.form.get('password')

    if customer_id in DEMO_USERS:

        user = DEMO_USERS[customer_id]

        if check_password_hash(user['password_hash'], password):

            session['customer_id'] = customer_id
            session['session_id'] = secrets.token_hex(16)

            features = extract_session_features(customer_id)

            risk_score, risk_level = calculate_risk_score(features)

            session['risk_score'] = risk_score
            session['risk_level'] = risk_level

            return redirect(url_for('dashboard'))

    return render_template('index.html', error="Invalid credentials")


@app.route('/dashboard')
def dashboard():

    if 'customer_id' not in session:
        return redirect(url_for('index'))

    customer_id = session['customer_id']

    # Extract session behavior features
    features = extract_session_features(customer_id)

    # Calculate risk
    risk_score, risk_level = calculate_risk_score(features)

    # ================= SECURITY MONITOR =================
    print("\n================ SECURITY MONITOR ================")

    if risk_level == "low":
        print("✅ NORMAL SESSION")
        print(f"Risk Score : {risk_score}")
        print(f"Risk Level : {risk_level.upper()}")

    elif risk_level == "medium":
        print("⚠️ SUSPICIOUS SESSION DETECTED")
        print(f"Risk Score : {risk_score}")
        print(f"Risk Level : {risk_level.upper()}")

    elif risk_level == "high":
        print("🚨🚨🚨 HIGH RISK ATTACK DETECTED 🚨🚨🚨")
        print(f"Risk Score : {risk_score}")
        print(f"Risk Level : {risk_level.upper()}")
        print("HONEYPOT ACTIVATED")

    print("=================================================\n")
    # ===================================================

    # Store internally (not shown to user)
    session['risk_score'] = risk_score
    session['risk_level'] = risk_level

    # If high risk → activate honeypot
    if risk_level == "high":

        print("⚠️ HIGH RISK DETECTED — HONEYPOT ACTIVATED")

        data = get_honeypot_data()

        account_data = data['account']
        transactions = data['transactions']

    else:

        user = DEMO_USERS[customer_id]

        account_data = {
            'customer_name': user['name'],
            'account_number': user['account_number'],
            'account_type': user['account_type'],
            'balance': user['balance'],
            'available_balance': user['available_balance']
        }

        transactions = REAL_TRANSACTIONS.get(customer_id, [])

    return render_template(
        'dashboard.html',
        account=account_data,
        transactions=transactions
    )


@app.route('/logout')
def logout():

    session.clear()

    return redirect(url_for('index'))


if __name__ == '__main__':

    if not load_model():
        print("Running without ML model")

    print("\nSecure Banking App running")
    print("Login: customer001 / SecurePass123!")

    app.run(debug=True)
