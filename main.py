import streamlit as st
import hashlib, base64, os, json, time
from cryptography.fernet import Fernet

#  constants cConfiguration section'
# to store data in json file
user_data_file = "users.json"
# salt for password hashing extra randomness
salt_for_hashing = b'secure_salt'
# to save encryption key in file Fernet
encryption_key_file = "fernet.key"
# Lockout time after 3 failed attempts
max_lockout_duration_in_seconds = 60

# Function to hash passkey ussing PBKDF2
def hash_passkey(passkey): 
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt_for_hashing, 100000)
    return base64.b64encode(key).decode()

#  load and save user daata in json
def load_users(): 
    if os.path.exists(user_data_file):
        with open(user_data_file, 'r') as f: return json.load(f)
    return {}

#
def save_users(data):
    with open(user_data_file, 'w') as f:
        json.dump(data, f)

# Cipher Setup in 'Fernet'
if "cipher" not in st.session_state: 
    generated_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(generated_key)

# initialize sessions variables
if "users" not in st.session_state: st.session_state.users = load_users()
if "current_user" not in st.session_state: st.session_state.current_user = None
if "failed_attempts" not in st.session_state: st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state: st.session_state.lockout_time = 0


# function for Encrypt , Decrypt 
def encrypt_data(text): return st.session_state.cipher.encrypt(text.encode()).decode()
def decrypt_data(encrypted_text): return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()


# Authenticate User and password here
def authenticate_user(username, password): 
    users = st.session_state.users
    hashed = hash_passkey(password)
    user = users.get(username)
    if user and user ["passkey"] == hashed: return True
    return False

# streamlit UI Section
st.title("🔐 Multi-User Secure Text Storage")
menu = ["Login", "Register", "Store Data", "Retrieve Data", "Logout", "FAQ"]
choice = st.sidebar.selectbox("Menu", menu)

#  Register New User here
if choice == "Register":
    st.subheader("📝 Register New User")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user and new_pass:
            users = st.session_state.users
            if new_user in users:
                st.warning("Username already exists!")
            else:
                users[new_user] = {
                    "passkey": hash_passkey(new_pass),
                    "data": {}
                }
                save_users(users)
                st.success("User registered successfully!")
        else: st.warning("Please fill in both fields.")


# User Login with username and password
elif choice == "Login":
    st.subheader("🔐 Login")
    user = st.text_input("Username")
    passwd = st.text_input("Password", type="password")
    if st.button("Login"):
        if authenticate_user(user, passwd):
            st.session_state.current_user = user
            st.session_state.failed_attempts = 0
            st.success(f"Welcome, {user}!")
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            st.error("Incorrect username or password.")


# Logout User   
elif choice == "Logout":
    st.session_state.current_user = None   
    st.success("Logged out successfully!")

# Stores Encrypted Data here
elif choice == "Store Data":
    if st.session_state.current_user:
        st.subheader("🔒 Store Your Data")
        label = st.text_input("Label (e.g., note1)")
        text = st.text_area("Text to encrypt")
        passkey = st.text_input("Your Passkey", type="password")
        if st.button("Save"):
            if label and text and passkey:
                encrypted = encrypt_data(text)
                hashed_key = hash_passkey(passkey)
                user_data = st.session_state.users[st.session_state.current_user]
                user_data["data"][label] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed_key
                }
                save_users(st.session_state.users)
                st.success(f"Data saved under label: `{label}`")
                st.code(encrypted)
            else:
                st.warning("All fields are required!!!")
    else:
        st.warning("Please log in first.")


# Retrieve Encrypted Data here
elif choice == "Retrieve Data":
    if st.session_state.current_user:
        st.subheader("🔓 Retrieve Your Data")
        label = st.text_input("Label")
        passkey = st.text_input("Passkey", type="password")

        current_time = time.time()
        if current_time < st.session_state.lockout_time:
            st.warning( Locked out due to failed attempts. Try again later.")
        else:
            if st.button("Retrieve"):
                if label and passkey:
                    user_data = st.session_state.users[st.session_state.current_user]["data"]
                    entry = user_data.get(label)
                    if entry and entry["passkey"] == hash_passkey(passkey):
                        try:
                            decrypted = decrypt_data(entry["encrypted_text"])
                            st.session_state.failed_attempts = 0
                            st.success("✅ Decrypted Text:")
                            st.code(decrypted)
                        except Exception:
                            st.error("🔐 Decryption failed. Corrupted data?")
                    else:
                        st.session_state.failed_attempts += 1
                        remaining = max(0, 3 - st.session_state.failed_attempts)
                        st.error(f"❌ Incorrect label or passkey. Attempts left: {remaining}")
                        if st.session_state.failed_attempts >= 3:
                            st.session_state.lockout_time = current_time + max_lockout_duration_in_seconds
                            st.warning("⚠️ Too many failed attempts. Locked for 1 minute.")
                else:
                    st.warning("Please fill both fields.")
    else:
        st.warning("Please log in first.")

# FAQ Section : additional feature from my site
elif choice == "FAQ":
    st.subheader("❓ FAQ")
    faq = {
        "What is this app for?": "It securely encrypts and stores your text.",
        "How is my data stored?": "Encrypted using Fernet and saved in a JSON file.",
        "Why can't I retrieve data?": "Wrong passkey or too many failed attempts.",
        "Is my passkey saved?": "Only a hashed version is stored.",
        "How many retries are allowed?": "3 attempts before a 1-minute lockout.",
        "Can I save multiple entries?": "Yes, each under a unique label.",
        "Is this production safe?": "No, it's a basic demo app.",
        "How is encryption done?": "Using Fernet from Python’s cryptography lib.",
        "Can I have multiple accounts?": "Yes, each user has their own vault."
    }
    question = st.selectbox("Select a question here:", list(faq.keys()))
    st.info(faq[question])
    
