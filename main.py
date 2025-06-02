import streamlit as st
import hashlib
import json
import time
import base64
import uuid
from cryptography.fernet import Fernet

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Generate Fernet key from passkey
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and \
           st.session_state.stored_data[data_id]['passkey'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Generate unique ID
def generate_data_id():
    return str(uuid.uuid4())

# Change page
def change_page(page):
    st.session_state.current_page = page

# UI Title
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Lockout
if st.session_state.failed_attempts >= 3:
    st.warning("🔒 Too many failed attempts! Please login.")
    st.session_state.current_page = 'Login'

# Home Page
if st.session_state.current_page == 'Home':
    st.header("🏠 Welcome")
    st.write("Securely store and retrieve data using passkeys.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data"):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data"):
            change_page("Retrieve Data")
    st.info(f"📦 Stored Entries: {len(st.session_state.stored_data)}")

# Store Data
elif st.session_state.current_page == 'Store Data':
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                data_id = generate_data_id()
                encrypted_text = encrypt_data(user_data, passkey)
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data encrypted and saved successfully!")
                st.code(data_id, language='text')
                st.info("💾 Save this Data ID to retrieve your data later.")
        else:
            st.error("⚠️ All fields are required.")

# Retrieve Data
elif st.session_state.current_page == 'Retrieve Data':
    st.subheader("🔍 Retrieve Data")
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)
                if decrypted_text:
                    st.success("✅ Decryption Successful!")
                    st.code(decrypted_text, language='text')
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Invalid passkey. Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login.")
                        st.session_state.current_page = 'Login'
                        st.experimental_rerun()
            else:
                st.error("❌ Data ID not found.")
        else:
            st.error("⚠️ All fields are required.")

# Login Page
elif st.session_state.current_page == 'Login':
    st.subheader("🔑 Login Required")
    login_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if login_pass == "admin123":
            st.success("✅ Reauthorized successfully.")
            st.session_state.failed_attempts = 0
            st.session_state.current_page = "Retrieve Data"
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")


                    


