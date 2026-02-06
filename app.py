import streamlit as st
import requests
import base64
import hashlib
import re
from datetime import datetime

# ---------------- CONFIG ----------------
ILAS_FILE_PATH = "IlASv5.1.py"  # path in repo
st.set_page_config(page_title="CAMP", layout="centered")

# ---------------- HELPERS ----------------
def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def github_headers():
    return {
        "Authorization": f"token {st.secrets['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }

# ---------------- AUTH ----------------
def advisor_login():
    st.title("🎓 CAMP Advisor Login")

    u = st.text_input("Advisor Username")
    p = st.text_input("Advisor Password", type="password")

    if st.button("Login"):
        if (
            sha256_hash(u) == st.secrets["ADVISOR_USER_HASH"]
            and sha256_hash(p) == st.secrets["ADVISOR_PASS_HASH"]
        ):
            st.session_state.advisor = True
            st.rerun()
        else:
            st.error("Invalid advisor credentials")

# ---------------- GITHUB OPS ----------------
def fetch_ilas_file():
    repo = st.secrets["GITHUB_REPO"]
    url = f"https://api.github.com/repos/{repo}/contents/{ILAS_FILE_PATH}"

    r = requests.get(url, headers=github_headers())
    if r.status_code != 200:
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
    st.caption("Manage course rep credentials securely")

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
            st.success("✅ Course rep credentials updated successfully")
            st.caption(f"Updated at {datetime.utcnow().isoformat()} UTC")
        else:
            st.error("❌ Update failed")

    st.divider()
    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()

# ---------------- MAIN ----------------
def main():
    if "advisor" not in st.session_state:
        st.session_state.advisor = False

    if not st.session_state.advisor:
        advisor_login()
    else:
        camp_dashboard()

if __name__ == "__main__":
    main()
