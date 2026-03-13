from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import hashlib
import secrets
import random

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ------------------------------------------------
# DEMO USER
# ------------------------------------------------

DEMO_USERS = {
    "customer001": {
        "password": "SecurePass123!",
        "name": "Alice Johnson",
        "account_number": "1234-5678",
        "account_type": "Checking",
        "balance": 12450.75
    }
}

# ------------------------------------------------
# REAL TRANSACTIONS
# ------------------------------------------------

REAL_TRANSACTIONS = {
    "customer001": [
        {
            "date": "2026-02-04",
            "description": "Salary Deposit",
            "amount": 4500,
            "type": "Credit",
            "status": "Completed"
        },
        {
            "date": "2026-02-03",
            "description": "Whole Foods",
            "amount": -125.43,
            "type": "Debit",
            "status": "Completed"
        },
        {
            "date": "2026-02-02",
            "description": "Netflix Subscription",
            "amount": -15.99,
            "type": "Online",
            "status": "Completed"
        }
    ]
}

# ------------------------------------------------
# GLOBAL TRACKERS
# ------------------------------------------------

session_data = {}
USER_DEVICES = {}
FAILED_LOGINS = {}
USER_RISK = {}

# FIX: Store failed login count per user BEFORE reset, so dashboard can use it
PRE_LOGIN_FAILED = {}

# ------------------------------------------------
# DEVICE FINGERPRINT
# ------------------------------------------------


def get_device():
    agent = request.headers.get("User-Agent", "")
    return hashlib.md5(agent.encode()).hexdigest()

# ------------------------------------------------
# GET IP
# ------------------------------------------------


def get_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0]
    return request.remote_addr

# ------------------------------------------------
# RANDOMIZED TRANSACTIONS
# ------------------------------------------------


def randomized_transactions():

    merchants = ["Amazon", "Uber", "Starbucks", "Walmart", "Netflix"]

    tx = []

    for i in range(5):

        amount = random.randint(10, 300)

        tx.append({
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": random.choice(merchants),
            "amount": -amount,
            "type": "Debit",
            "status": "Completed"
        })

    return tx

# ------------------------------------------------
# HONEYPOT DATA
# ------------------------------------------------


def honeypot_data():

    fake_balance = random.randint(200, 400)

    merchants = ["Amazon", "Target", "Shell", "Uber"]

    tx = []

    for i in range(5):

        amount = random.randint(5, 120)

        tx.append({
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": random.choice(merchants),
            "amount": -amount,
            "type": "Debit",
            "status": "Completed"
        })

    return fake_balance, tx

# ------------------------------------------------
# RISK ENGINE
# ------------------------------------------------


def calculate_risk(previous_risk, activity):

    risk = previous_risk

    if activity["new_device"]:
        risk += 6

    if activity["new_location"]:
        risk += 4

    if activity["failed_logins"] > 0:
        risk += 3

    if activity["failed_logins"] > 2:
        risk += 5

    if activity["failed_logins"] > 5:
        risk += 10

    if activity["failed_logins"] > 10:
        risk += 15

    if activity["failed_logins"] > 15:
        risk += 25

    if activity["rapid_requests"]:
        risk += 2

    if activity["unusual_time"]:
        risk += 2

    return min(risk, 100)

# ------------------------------------------------
# SECURITY LOG
# ------------------------------------------------


def security_log(user, risk, activity):

    print("\n🚨========== AI SECURITY MONITOR ==========")
    print("USER :", user)
    print("RISK SCORE :", risk)

    if risk <= 40:
        print("STATUS : SAFE")
    elif risk <= 75:
        print("STATUS : SUSPICIOUS")
    else:
        print("STATUS : HIGH RISK ATTACK")

    print("\nACTIVITY FLAGS")

    for k, v in activity.items():
        print(f"{k} : {v}")

    print("===========================================\n")

# ------------------------------------------------
# HOME
# ------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")

# ------------------------------------------------
# LOGIN
# ------------------------------------------------


@app.route("/login", methods=["POST"])
def login():

    cid = request.form.get("customer_id")
    password = request.form.get("password")

    if cid not in FAILED_LOGINS:
        FAILED_LOGINS[cid] = 0

    if cid not in USER_RISK:
        USER_RISK[cid] = 15

    # CORRECT LOGIN
    if cid in DEMO_USERS and password == DEMO_USERS[cid]["password"]:

        # FIX 1: Save the failed login count BEFORE resetting it
        # so the dashboard's first risk calculation still sees it
        PRE_LOGIN_FAILED[cid] = FAILED_LOGINS[cid]

        FAILED_LOGINS[cid] = 0  # reset attempts but keep risk

        device = get_device()

        if cid not in USER_DEVICES:
            USER_DEVICES[cid] = device

        session["customer_id"] = cid
        session["session_id"] = secrets.token_hex(16)

        # FIX 2: Calculate and apply risk from failed attempts at login time
        # so USER_RISK is already updated before dashboard loads
        activity = {
            "new_device": device != USER_DEVICES.get(cid, device),
            "new_location": False,  # no previous IP to compare at login
            "failed_logins": PRE_LOGIN_FAILED[cid],
            "rapid_requests": False,
            "unusual_time": datetime.now().hour < 6
        }

        login_risk = calculate_risk(USER_RISK[cid], activity)
        # risk never decreases
        USER_RISK[cid] = max(USER_RISK[cid], login_risk)

        session["risk_score"] = USER_RISK[cid]

        session_data[session["session_id"]] = {
            "start": datetime.now(),
            "ip": get_ip(),
            "device": device,
            "requests": 0
        }

        security_log(cid, USER_RISK[cid], activity)

        return redirect(url_for("dashboard"))

    # FAILED LOGIN
    else:

        FAILED_LOGINS[cid] += 1
        count = FAILED_LOGINS[cid]

        if count <= 3:
            USER_RISK[cid] += 2
        elif count <= 6:
            USER_RISK[cid] += 5
        elif count <= 10:
            USER_RISK[cid] += 8
        else:
            USER_RISK[cid] += 12

        activity = {
            "new_device": False,
            "new_location": False,
            "failed_logins": FAILED_LOGINS[cid],
            "rapid_requests": False,
            "unusual_time": datetime.now().hour < 6
        }

        security_log(cid, USER_RISK[cid], activity)

        return render_template(
            "index.html",
            error="Invalid Customer ID or Password"
        )

# ------------------------------------------------
# DASHBOARD
# ------------------------------------------------


@app.route("/dashboard")
def dashboard():

    if "customer_id" not in session:
        return redirect(url_for("index"))

    cid = session["customer_id"]

    data = session_data[session["session_id"]]

    data["requests"] += 1

    activity = {
        "new_device": get_device() != USER_DEVICES[cid],
        "new_location": get_ip() != data["ip"],
        # FIX 3: Use PRE_LOGIN_FAILED so dashboard still sees the failed
        # attempts that happened before this session, not the reset value
        "failed_logins": PRE_LOGIN_FAILED.get(cid, 0),
        "rapid_requests": data["requests"] > 15,
        "unusual_time": datetime.now().hour < 6
    }

    new_risk = calculate_risk(USER_RISK[cid], activity)

    # Risk should NEVER decrease
    risk_score = max(USER_RISK[cid], new_risk)

    USER_RISK[cid] = risk_score
    session["risk_score"] = risk_score

    security_log(cid, risk_score, activity)

    user = DEMO_USERS[cid]

    real_balance = user["balance"]

    # LOW RISK
    if risk_score <= 40:

        account_data = {
            "customer_name": user["name"],
            "account_number": user["account_number"],
            "account_type": user["account_type"],
            "balance": real_balance,
            "available_balance": real_balance
        }

        transactions = REAL_TRANSACTIONS[cid]

    # MEDIUM RISK
    elif risk_score <= 75:

        account_data = {
            "customer_name": user["name"],
            "account_number": user["account_number"],
            "account_type": user["account_type"],
            "balance": real_balance,
            "available_balance": real_balance
        }

        transactions = randomized_transactions()

    # HIGH RISK
    else:

        fake_balance, transactions = honeypot_data()

        account_data = {
            "customer_name": user["name"],
            "account_number": user["account_number"],
            "account_type": user["account_type"],
            "balance": fake_balance,
            "available_balance": fake_balance
        }

    return render_template(
        "dashboard.html",
        account=account_data,
        transactions=transactions
    )

# ------------------------------------------------
# LOGOUT
# ------------------------------------------------


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ------------------------------------------------
# RUN
# ------------------------------------------------


if __name__ == "__main__":

    print("\n🔐 SecureBank AI Fraud Detection System Started")
    print("Login: customer001 / SecurePass123!")

    app.run(debug=True)
