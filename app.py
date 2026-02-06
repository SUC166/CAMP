import streamlit as st
import requests
import base64
import hashlib
import re
from datetime import datetime

# ---------------- CONFIG ----------------
ILAS_FILE_PATH = "app.py"
st.set_page_config(page_title="CAMP", layout="centered")

# ---------------- AUTH CONFIG (SHA-256 HASHES) ----------------
# username: advisor
# password: change_me
ADVISOR_USER_HASH = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
ADVISOR_PASS_HASH = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"

# ---------------- HELPERS ----------------
def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def github_headers():
    return {
        "Authorization": f"token {st.secrets['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }

# ---------------- AUTH ----------------
def login_page():
    st.title("🎓 CAMP Advisor Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if (
            sha256_hash(username) == ADVISOR_USER_HASH
            and sha256_hash(password) == ADVISOR_PASS_HASH
        ):
            st.session_state.logged_in = True
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid credentials")

def logout():
    st.session_state.clear()
    st.rerun()

# ---------------- GITHUB OPS ----------------
def fetch_ilas_file():
    repo = st.secrets["GITHUB_REPO"]
    url = f"https://api.github.com/repos/{repo}/contents/{ILAS_FILE_PATH}"

    r = requests.get(url, headers=github_headers())
    if r.status_code != 200:
        st.error("Failed to fetch ILAS file")
        st.stop()

    data = r.json()
    code = base64.b64decode(data["content"]).decode()
    return code, data["sha"]

def update_rep_credentials(code, user_hash, pass_hash):
    code = re.sub(
        r'REP_NAME\s*=\s*".*?"',
        f'REP_NAME = "{user_hash}"',
        code
    )
    code = re.sub(
        r'REP_PASS\s*=\s*".*?"',
        f'REP_PASS = "{pass_hash}"',
        code
    )
    return code

def push_ilas_file(updated_code, sha):
    repo = st.secrets["GITHUB_REPO"]
    url = f"https://api.github.com/repos/{repo}/contents/{ILAS_FILE_PATH}"

    encoded = base64.b64encode(updated_code.encode()).decode()

    payload = {
        "message": "CAMP: Update course rep credentials",
        "content": encoded,
        "sha": sha
    }

    r = requests.put(url, headers=github_headers(), json=payload)
    return r.status_code in (200, 201)

# ---------------- DASHBOARD ----------------
def camp_dashboard():
    st.title("🛠️ Course Advisory & Management Platform (CAMP)")
    st.caption("Secure course rep credential manager")

    st.divider()

    rep_user = st.text_input("New Course Rep Username")
    rep_pass = st.text_input("New Course Rep Password", type="password")

    if st.button("🚀 Update Course Rep"):
        if not rep_user or not rep_pass:
            st.error("All fields are required")
            return

        with st.spinner("Updating ILAS credentials..."):
            code, sha = fetch_ilas_file()
            updated = update_rep_credentials(
                code,
                sha256_hash(rep_user),
                sha256_hash(rep_pass)
            )
            ok = push_ilas_file(updated, sha)

        if ok:
            st.success("✅ Course rep credentials updated")
            st.caption(f"Updated at {datetime.utcnow().isoformat()} UTC")
        else:
            st.error("❌ Update failed")

    st.divider()
    if st.button("Logout"):
        logout()

# ---------------- MAIN ----------------
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
    else:
        camp_dashboard()

if __name__ == "__main__":
    main()
