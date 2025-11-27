import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import bcrypt

# Setup stuff - copied from online tutorial
st.set_page_config(page_title="Security App", layout="wide")
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user' not in st.session_state:
    st.session_state.user = None
if 'role' not in st.session_state:
    st.session_state.role = None


# Database functions - i think this is right
def get_db():
    return sqlite3.connect('DATA/intelligence_platform.db')

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cyber_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT,
            reported_by TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def check_login(u, p):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, role FROM users WHERE username=?", (u,))
    user = cursor.fetchone()
    conn.close()
    if user and bcrypt.checkpw(p.encode('utf-8'), user[0].encode('utf-8')):
        return True, user[1]
    return False, None


def create_user(u, p, role="user"):
    if not u or not p or len(p) < 8 or ' ' in u or not u.isalnum():
        return False, "Invalid input"
    conn = get_db()
    cursor = conn.cursor()
    if cursor.execute("SELECT username FROM users WHERE username=?", (u,)).fetchone():
        return False, "Username taken"
    pw_hash = bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",(u, pw_hash.decode('utf-8'), role))
    conn.commit()
    conn.close()
    return True, "User created"


# CRUD stuff for incidents - this took forever to figure out
def get_incidents():
    conn = get_db()
    df = pd.read_sql("SELECT * FROM cyber_incidents ORDER BY id DESC", conn)
    conn.close()
    return df


def get_incident_by_id(incident_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cyber_incidents WHERE id = ?", (incident_id,))
    incident = cursor.fetchone()
    conn.close()
    return incident


def add_incident(t, s, sts, d, u):
    if not t or not d:
        return False, "Required fields missing"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by) VALUES (?, ?, ?, ?, ?, ?)",(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t, s, sts, d, u))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return True, new_id


def update_incident(incident_id, incident_type, severity, status, description):
    if not incident_type or not description:
        return False, "Required fields missing"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cyber_incidents SET incident_type = ?, severity = ?, status = ?, description = ? WHERE id = ?",(incident_type, severity, status, description, incident_id))
    conn.commit()
    conn.close()
    return True, "Updated"


def update_status(incident_id, status):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE cyber_incidents SET status = ? WHERE id = ?", (status, incident_id))
    conn.commit()
    conn.close()
    return True, "Status updated"


def remove_incident(incident_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
    conn.commit()
    conn.close()
    return True, "Deleted"


def get_all_users():
    conn = get_db()
    df = pd.read_sql("SELECT id, username, role FROM users", conn)
    conn.close()
    return df


def update_user_role(user_id, new_role):
    if new_role not in ["user", "analyst", "admin"]:
        return False, "Invalid role"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return True, "Role updated"


def delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True, "User deleted"


# Main app function - finally got this working
def main():
    init_db()
    print("App started")  # debug print, forgot to remove

    if not st.session_state.logged_in:
        st.title("🔐 Login")
        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab1:
            with st.form("login"):
                u = st.text_input("Username")
                p = st.text_input("Password", type="password")
                if st.form_submit_button("Login"):
                    if u and p:
                        success, role = check_login(u, p)
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.user = u
                            st.session_state.role = role
                            st.rerun()
                        else:
                            st.error("Invalid credentials")
                    else:
                        st.error("All fields required")

        with tab2:
            with st.form("register"):
                new_u = st.text_input("Username")
                new_p = st.text_input("Password", type="password")
                confirm_p = st.text_input("Confirm Password", type="password")
                role = st.selectbox("Role", ["user", "analyst", "admin"])
                if st.form_submit_button("Register"):
                    if new_p != confirm_p:
                        st.error("Passwords do not match")
                    else:
                        success, msg = create_user(new_u, new_p, role)
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.user = new_u
                            st.session_state.role = role
                            st.rerun()
                        else:
                            st.error(msg)

    else:
        st.sidebar.title(f"Hi {st.session_state.user}")
        st.sidebar.write(f"Role: {st.session_state.role}")

        domain = st.sidebar.selectbox("Domain", ["Cyber", "Data", "IT"])
        page = st.sidebar.radio("Go to", ["Dashboard", "Incidents", "Analytics", "Admin"])

        data = get_incidents()
        print(f"Loaded {len(data)} incidents")  # another debug print

        if page == "Dashboard":
            st.title("Dashboard")
            # Filtering logic, a bit messy but works
            if domain == "Cyber":
                filtered_data = data[data['incident_type'] == 'Phishing']
            elif domain == "Data":
                filtered_data = data[data['severity'] == 'High']
            else:
                filtered_data = data
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Incidents", len(filtered_data))
            with col2:
                st.metric("Serious", len(filtered_data[filtered_data["severity"].isin(['High', 'Critical'])]))
            with col3:
                st.metric("Open", len(filtered_data[filtered_data["status"] == 'Open']))
            st.dataframe(filtered_data.head(), use_container_width=True)

        elif page == "Incidents":
            if st.session_state.role not in ['admin', 'analyst']:
                st.error("Access denied: Analyst or Admin role required")
                st.stop()

            st.title("Incident Management")

            # CREATE - Add new incident
            with st.form("add_incident"):
                st.subheader("Add New Incident")
                col1, col2, col3 = st.columns(3)
                with col1:
                    t = st.text_input("Incident Type*", placeholder="Phishing, Malware, etc.")
                with col2:
                    s = st.selectbox("Severity*", ["Low", "Medium", "High", "Critical"])
                with col3:
                    sts = st.selectbox("Status*", ["Open", "In Progress", "Resolved"])

                d = st.text_area("Description*", placeholder="Enter incident details...")

                if st.form_submit_button("➕ Add Incident"):
                    success, result = add_incident(t, s, sts, d, st.session_state.user)
                    if success:
                        st.success(f"Incident #{result} added!")
                        st.rerun()
                    else:
                        st.error(result)

            st.divider()

            # READ - Display incidents table with inline actions
            st.subheader("All Incidents")

            if len(data) > 0:
                # Display the table
                st.dataframe(data, use_container_width=True)

                st.divider()

                # UPDATE & DELETE operations
                col1, col2 = st.columns(2)

                with col1:
                    with st.form("update_incident"):
                        st.subheader("Update Incident")
                        incident_id = st.selectbox("Select Incident", data['id'].tolist(), key="update")
                        incident = get_incident_by_id(incident_id)

                        if incident:
                            col1_form, col2_form = st.columns(2)
                            with col1_form:
                                new_t = st.text_input("Type", value=incident[2])
                                new_s = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"],index=["Low", "Medium", "High", "Critical"].index(incident[3]))
                            with col2_form:
                                new_sts = st.selectbox("Status", ["Open", "In Progress", "Resolved"],index=["Open", "In Progress", "Resolved"].index(incident[4]))

                            new_d = st.text_area("Description", value=incident[5])

                            if st.form_submit_button("🔄 Update Incident"):
                                success, msg = update_incident(incident_id, new_t, new_s, new_sts, new_d)
                                if success:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)

                with col2:
                    with st.form("delete_incident"):
                        st.subheader("Delete Incident")
                        del_incident_id = st.selectbox("Select Incident", data['id'].tolist(), key="delete")
                        incident = get_incident_by_id(del_incident_id)

                        if incident:
                            st.warning(f"⚠️ Delete Incident #{del_incident_id}?")
                            st.write(f"**Type:** {incident[2]}")
                            st.write(f"**Severity:** {incident[3]}")
                            st.write(f"**Status:** {incident[4]}")

                            if st.form_submit_button("🗑️ Confirm Delete"):
                                success, msg = remove_incident(del_incident_id)
                                if success:
                                    st.success(msg)
                                    st.rerun()

            else:
                st.info("No incidents found.")

        elif page == "Analytics":
            st.title("Analytics")
            if len(data) > 0:
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("By Type")
                    type_df = pd.DataFrame({'Type': data['incident_type'].value_counts().index,'Count': data['incident_type'].value_counts().values})
                    st.bar_chart(type_df, x='Type', y='Count')
                with col2:
                    st.subheader("By Severity")
                    sev_df = pd.DataFrame({'Severity': data['severity'].value_counts().index,'Count': data['severity'].value_counts().values})
                    st.bar_chart(sev_df, x='Severity', y='Count')

                st.subheader("Severity by Status")
                pivot_data = pd.crosstab(data['status'], data['severity'])
                st.bar_chart(pivot_data)
            else:
                st.info("No data available")

        elif page == "Admin":
            if st.session_state.role != 'admin':
                st.error("Access denied: Admin role required")
                st.stop()
            st.title("Admin Tools")

            tab1, tab2 = st.tabs(["Incident Management", "User Management"])

            with tab1:
                st.subheader("Quick Incident Operations")
                if len(data) > 0:
                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("**Update Status**")
                        incident_id = st.selectbox("Select Incident", data['id'].tolist(), key="admin_update")
                        new_status = st.selectbox("New Status", ["Open", "In Progress", "Resolved"])
                        if st.button("Update Status"):
                            success, msg = update_status(incident_id, new_status)
                            if success:
                                st.success(msg)
                                st.rerun()

                    with col2:
                        st.write("**Delete Incident**")
                        incident_to_delete = st.selectbox("Incident to Delete", data['id'].tolist(), key="admin_delete")
                        if st.button("Delete Incident"):
                            success, msg = remove_incident(incident_to_delete)
                            if success:
                                st.success(msg)
                                st.rerun()
                else:
                    st.info("No incidents available")

            with tab2:
                st.subheader("User Management")
                users_data = get_all_users()
                st.dataframe(users_data, use_container_width=True)

                if len(users_data) > 0:
                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("**Update User Role**")
                        user_id = st.selectbox("Select User", users_data['id'].tolist())
                        current_role = users_data[users_data['id'] == user_id]['role'].iloc[0]
                        new_role = st.selectbox("New Role", ["user", "analyst", "admin"],index=["user", "analyst", "admin"].index(current_role))

                        if st.button("Update Role"):
                            success, msg = update_user_role(user_id, new_role)
                            if success:
                                st.success(msg)
                                st.rerun()

                    with col2:
                        st.write("**Delete User**")
                        user_to_delete = st.selectbox("User to Delete",users_data[users_data['username'] != st.session_state.user]['id'].tolist(), key="user_del")

                        if st.button("Delete User"):
                            success, msg = delete_user(user_to_delete)
                            if success:
                                st.success(msg)
                                st.rerun()

        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.role = None
            st.rerun()

if __name__ == "__main__":
    main()

