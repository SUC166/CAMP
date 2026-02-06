import streamlit as st
import requests
import base64
import hashlib
import re
from datetime import datetime

# ---------------- CONFIG ----------------
ILAS_FILE_PATH = "app.py"
st.set_page_config(page_title="CAMP", layout="centered")

# ---------------- AUTH CONFIG ----------------
ADVISOR_USER_HASH = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
ADVISOR_PASS_HASH = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"

# ---------------- GPA CONFIG ----------------
GRADE_POINTS = {
    "A": 5.0,
    "B": 4.0,
    "C": 3.0,
    "D": 2.0,
    "E": 1.0,
    "F": 0.0,
}

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
    st.title("🛠️ CAMP Dashboard")
    st.caption("Course Advisory & Management Platform")

    st.divider()

    rep_user = st.text_input("New Course Rep Username")
    rep_pass = st.text_input("New Course Rep Password", type="password")

    if st.button("🚀 Update Course Rep"):
        if not rep_user or not rep_pass:
            st.error("All fields are required")
            return

        code, sha = fetch_ilas_file()
        updated = update_rep_credentials(
            code,
            sha256_hash(rep_user),
            sha256_hash(rep_pass)
        )
        ok = push_ilas_file(updated, sha)

        if ok:
            st.success("✅ Course rep credentials updated")
        else:
            st.error("❌ Update failed")

# ---------------- CGPA PAGE ----------------
def cgpa_calculator():
    st.title("📊 CGPA Calculator (FUTO)")

    if "courses" not in st.session_state:
        st.session_state.courses = []

    with st.form("add_course"):
        c1, c2, c3 = st.columns(3)
        name = c1.text_input("Course Name")
        units = c2.number_input("Units", min_value=1, max_value=6, step=1)
        grade = c3.selectbox("Grade", list(GRADE_POINTS.keys()))

        if st.form_submit_button("➕ Add Course"):
            st.session_state.courses.append({
                "name": name,
                "units": units,
                "grade": grade
            })

    st.divider()

    total_units = 0
    total_points = 0.0

    if st.session_state.courses:
        st.subheader("Entered Courses")

        for c in st.session_state.courses:
            gp = GRADE_POINTS[c["grade"]]
            wp = gp * c["units"]
            total_units += c["units"]
            total_points += wp

            st.write(
                f"{c['name']} — {c['units']} units — {c['grade']} ({wp})"
            )

        st.divider()
        st.write(f"**Total Units:** {total_units}")
        st.write(f"**Total Weighted Points:** {total_points}")

        if total_units < 15:
            st.warning("Minimum of 15 units required")
        elif total_units > 30:
            st.error("Maximum of 30 units exceeded")
        else:
            gpa = round(total_points / total_units, 2)
            st.success(f"🎓 GPA: {gpa}")

    st.divider()
    c1, c2 = st.columns(2)

    if c1.button("♻️ Clear Grades Only"):
        for c in st.session_state.courses:
            c["grade"] = "A"
        st.rerun()

    if c2.button("🗑️ Clear All"):
        st.session_state.courses = []
        st.rerun()

# ---------------- MAIN ----------------
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    page = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "CGPA Calculator"]
    )

    if st.sidebar.button("Logout"):
        logout()

    if page == "Dashboard":
        camp_dashboard()
    else:
        cgpa_calculator()

if __name__ == "__main__":
    main()
