# 🔐 Password Strength & Breach Detection Tool
# Author: Hammad Tahir
# Description: A CLI tool to evaluate password strength and check if it's leaked in any known data breaches.

import re              # For pattern matching (e.g., checking for digits, symbols)
import hashlib         # For hashing password using SHA-1
import requests        # For making API requests to HaveIBeenPwned

# -------------------------------
# Function to check password strength
# -------------------------------
def check_strength(password):
    length_ok = len(password) >= 8
    has_upper = re.search(r'[A-Z]', password)
    has_lower = re.search(r'[a-z]', password)
    has_digit = re.search(r'\d', password)
    has_symbol = re.search(r'[!@#$%^&*()\-_=+[\]{};:\'",.<>/?\\|`~]', password)

    # Calculate strength score based on criteria
    score = sum([
        bool(length_ok),
        bool(has_upper),
        bool(has_lower),
        bool(has_digit),
        bool(has_symbol)
    ])

    # Decide strength level
    if score == 5:
        strength = "Very Strong 💪"
    elif score == 4:
        strength = "Strong 🔐"
    elif score == 3:
        strength = "Moderate ⚠️"
    else:
        strength = "Weak ❌"

    return {
        "Length OK": length_ok,
        "Uppercase": bool(has_upper),
        "Lowercase": bool(has_lower),
        "Digit": bool(has_digit),
        "Symbol": bool(has_symbol),
        "Strength": strength
    }

# -------------------------------
# Function to check password breach using HaveIBeenPwned API
# -------------------------------
def check_password_breach(password):
    # Convert password to SHA-1 hash
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]     # First 5 characters of the hash
    suffix = sha1[5:]     # Remaining characters

    # API URL for k-anonymity
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    # Check if API call was successful
    if res.status_code != 200:
        raise RuntimeError(f"API error: {res.status_code}")

    # Process the response to find match
    hashes = res.text.splitlines()
    for line in hashes:
        h_suffix, count = line.split(":")
        if h_suffix == suffix:
            return int(count)  # Password found in breaches

    return 0  # Password not found in breaches

# -------------------------------
# Main Program Starts Here
# -------------------------------
print("🔐 Password Strength & Breach Detection Tool 🔎")
password = input("Enter your password: ")

# 1. Check strength
strength_report = check_strength(password)

# 2. Check breach
breach_count = check_password_breach(password)

# -------------------------------
# Display Strength Report
# -------------------------------
print("\n🔍 Password Analysis:")
for key, value in strength_report.items():
    print(f"{key}: {value}")

print(f"\n🛡️ Overall Strength: {strength_report['Strength']}")

# -------------------------------
# Display Breach Result
# -------------------------------
if breach_count:
    print(f"❌ WARNING: This password has been found in {breach_count} data breaches!")
    print("⚠️ Please avoid using this password.")
else:
    print("✅ This password was NOT found in any known breaches. Looks safe!")

