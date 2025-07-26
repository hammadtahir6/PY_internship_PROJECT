import re
import hashlib
import requests
import gradio as gr

# --- Phase 1: Password Strength Check ---
def check_password_strength(password):
    strength_report = {
        "Length OK": len(password) >= 8,
        "Uppercase": bool(re.search(r"[A-Z]", password)),
        "Lowercase": bool(re.search(r"[a-z]", password)),
        "Digit": bool(re.search(r"\d", password)),
        "Symbol": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }

    score = sum(strength_report.values())

    if score == 5:
        strength = "Very Strong 🔐"
    elif score >= 4:
        strength = "Strong ✅"
    elif score == 3:
        strength = "Moderate ⚠️"
    else:
        strength = "Weak ❌"

    strength_report["Strength"] = strength
    return strength_report

# --- Phase 2: Breach Check via HIBP ---
def check_password_breach(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pass[:5], sha1pass[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        return "Error contacting breach API"

    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)

    return 0

# --- Combined Gradio App ---
def analyze_password(password):
    if not password:
        return "❌ Please enter a password", None

    strength_info = check_password_strength(password)
    breaches = check_password_breach(password)

    strength_output = "\n".join([f"{k}: {v}" for k, v in strength_info.items()])

    if breaches == "Error contacting breach API":
        breach_msg = "⚠️ Could not reach HaveIBeenPwned API"
    elif breaches > 0:
        breach_msg = f"❌ Password found in {breaches} breaches! Change it!"
    else:
        breach_msg = "✅ Password not found in known breaches"

    return strength_output, breach_msg

# --- Gradio Interface ---
with gr.Blocks(theme=gr.themes.Soft()) as app:
    gr.Markdown("# 🔐 Password Strength & Breach Detection Tool")
    gr.Markdown("Enter your password below to analyze its strength and check if it has been exposed in data breaches.")

    with gr.Row():
        password_input = gr.Textbox(type="password", label="Enter Password", placeholder="Your password...")

    with gr.Row():
        analyze_btn = gr.Button("🔍 Analyze Password")

    with gr.Row():
        strength_output = gr.Textbox(label="🧠 Strength Analysis", lines=6)
        breach_output = gr.Textbox(label="🛡️ Breach Check Result", lines=2)

    analyze_btn.click(analyze_password, inputs=password_input, outputs=[strength_output, breach_output])

# --- Launch App ---
app.launch()
