import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# ========== CONFIG ==========
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
MASTER_PASSWORD = "admin123"  # In real-world, don't hardcode it!
DATA_FILE = "stored_data.json"
LOCKOUT_TIME = 30  # seconds

# ========== INITIAL SETUP ==========
stored_data = {}
failed_attempts = st.session_state.get("failed_attempts", 0)
lockout_time = st.session_state.get("lockout_time", None)

# Load data if exists
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)

# ========== FUNCTIONS ==========
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

def check_lockout():
    if lockout_time:
        elapsed = time.time() - lockout_time
        if elapsed < LOCKOUT_TIME:
            remaining = int(LOCKOUT_TIME - elapsed)
            st.error(f"🔒 Locked out! Please wait {remaining} seconds.")
            st.stop()
        else:
            st.session_state.lockout_time = None
            st.session_state.failed_attempts = 0

# ========== STREAMLIT UI ==========
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Use this app to **securely store and retrieve your private data** using encrypted passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter a Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data()
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    check_lockout()

    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            hashed_passkey = hash_passkey(passkey)

            if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed_passkey:
                decrypted_text = decrypt_data(encrypted_text)
                st.success(f"✅ Decrypted Data: {decrypted_text}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time()
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.success("✅ Reauthorized successfully! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")
