import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import bcrypt
import os

#page set up
st.set_page_config(page_title="Security App", layout="wide")
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# Data access functions
def get_excel_data(file_path):
    try:
        if os.path.exists(file_path):
            df = pd.read_excel(file_path)
            return df
        else:
            return pd.DataFrame()
    except Exception as e:
        st.error(f"Error reading {file_path}: {str(e)[:100]}")
        return pd.DataFrame()


def get_cyber_excel_data():
    return get_excel_data("DATA/cyber_incidents.xlsx")


def get_it_tickets_excel():
    return get_excel_data("DATA/it_tickets.xlsx")


def get_datasets_metadata():
    return get_excel_data("DATA/datasets_metadata.xlsx")

def migrate_all_data():
    conn = get_db()
    cyber_df = get_cyber_excel_data()
    if not cyber_df.empty:
        if 'timestamp' in cyber_df.columns:
            cyber_df = cyber_df.rename(columns={'timestamp': 'date'})

        if 'category' in cyber_df.columns:
            cyber_df = cyber_df.rename(columns={'category': 'incident_type'})

        if 'incident_id' in cyber_df.columns:
            cyber_df = cyber_df.drop(columns=['incident_id'])

        if 'reported_by' not in cyber_df.columns:
            cyber_df['reported_by'] = 'admin'

        correct_order = ['date', 'incident_type', 'severity', 'status', 'description', 'reported_by']

        cyber_df = cyber_df[correct_order]

        cyber_df.to_sql('cyber_incidents', conn, if_exists='replace', index=False)
        st.success(f"Migrated {len(cyber_df)} cyber incidents")

        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM cyber_incidents')
        db_count = cursor.fetchone()[0]

    else:
        st.error("No cyber incidents found")
        conn.close()
        return False

    datasets_df = get_datasets_metadata()
    if not datasets_df.empty:
        datasets_df.to_sql('datasets_metadata', conn, if_exists='replace', index=False)
        st.success(f"Migrated {len(datasets_df)} datasets")

    it_df = get_it_tickets_excel()
    if not it_df.empty:
        it_df.to_sql('it_tickets', conn, if_exists='replace', index=False)
        st.success(f"Migrated {len(it_df)} IT tickets")

    conn.close()
    st.success("Data migration complete!")
    return True


def get_db():
    return sqlite3.connect("DATA/intelligence_platform.db")


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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS datasets_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            asset_type TEXT,
            classification TEXT,
            owner TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS it_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            category TEXT,
            priority TEXT,
            status TEXT
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
    if user and bcrypt.checkpw(p.encode("utf-8"), user[0].encode("utf-8")):
        return True, user[1]
    return False, None


def create_user(u, p, role="user"):
    if not u or not p or len(p) < 8 or ' ' in u or not u.isalnum():
        return False, "Invalid input"
    conn = get_db()
    cursor = conn.cursor()
    if cursor.execute("SELECT username FROM users WHERE username=?", (u,)).fetchone():
        return False, "Username already exists"
    pw_hash = bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   (u, pw_hash.decode("utf-8"), role))
    conn.commit()
    conn.close()
    return True, "User created"

def get_incidents():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cyber_incidents")
        rows = cursor.fetchall()
        cursor.execute("PRAGMA table_info(cyber_incidents)")
        columns_info = cursor.fetchall()
        columns = [col[1] for col in columns_info]
        conn.close()

        if rows:
            df = pd.DataFrame(rows, columns = columns)
            return df
        else:
            return pd.DataFrame()
    except Exception as e:
        st.error(f"Error loading incidents: {str(e)[:100]}")
        return pd.DataFrame()

def get_incident_by_id(incident_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cyber_incidents WHERE id = ?", (incident_id,))
    incident = cursor.fetchone()
    conn.close()
    return incident

def add_incident_to_db(t, s, sts, d, u):
    if not t or not d:
        return False, "Required fields are missing"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t, s, sts, d, u))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return True, new_id

def update_incident(incident_id, incident_type, severity, status, description):
    if not incident_type or not description:
        return False, "Required fields are missing"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cyber_incidents SET incident_type = ?, severity = ?, status = ?, description = ? WHERE id = ?",
        (incident_type, severity, status, description, incident_id))
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
    try:
        conn = get_db()
        df = pd.read_sql("SELECT id, username, role FROM users", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


def get_it_tickets_db():
    try:
        conn = get_db()
        df = pd.read_sql_query("SELECT * FROM it_tickets", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


def add_it_ticket(title, category, priority):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO it_tickets (title, category, priority, status) VALUES (?, ?, ?, ?)",
        (title, category, priority, "Open")
    )
    conn.commit()
    conn.close()
    return True


def get_datasets_metadata_db():
    try:
        conn = get_db()
        df = pd.read_sql_query("SELECT * FROM datasets_metadata", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


def add_datasets_metadata(name, asset_type, classification, owner):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO datasets_metadata (name, asset_type, classification, owner) VALUES (?, ?, ?, ?)",
                   (name, asset_type, classification, owner)
                   )
    conn.commit()
    conn.close()
    return True


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


def main():
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        pw_hash =  bcrypt.hashpw("admin123".encode("utf-8"), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ("admin", pw_hash.decode("utf-8"), "admin"))
        conn.commit()
        print("Created default user")
    conn.close()
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
                            st.success("Logged in successfully")
                            st.rerun()
                        else:
                            st.error("Invalid credentials")
                    else:
                        st.error("All fields are required")

        with tab2:
            with st.form("register"):
                new_u = st.text_input("Username")
                new_p = st.text_input("Password", type="password")
                confirm_p = st.text_input("Confirm Password", type="password")
                role = st.selectbox("Role", ["user", "analyst", "admin"])
                if st.form_submit_button("Register"):
                    if new_p != confirm_p:
                        st.error("Passwords don't match")
                    else:
                        success, msg = create_user(new_u, new_p, role)
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.user = new_u
                            st.session_state.role = role
                            st.success("Registered successfully")
                            st.rerun()
                        else:
                            st.error(msg)

    else:
        st.sidebar.title(f"Hi {st.session_state.user}")
        st.sidebar.text(f"Role: {st.session_state.role}")

        if st.session_state.role in ["admin", "analyst"]:
            if st.sidebar.button("Migrate Excel to DB"):
                migrate_all_data()

        domain = st.sidebar.selectbox("Domain", ["Cyber", "Data", "IT"])
        page = st.sidebar.radio("Go to", ["Dashboard", "Incidents", "Analytics", "Admin"])

        st.sidebar.divider()
        st.sidebar.subheader("AI Assistant")
        if st.sidebar.button("Gemini Interactive Chat"):
            st.switch_page("pages/gemini_interactive.py")

        data = get_incidents()

        if page == "Dashboard":
            st.title(f"{domain} Dashboard")

            if domain == "Cyber":
                cyber_data = get_incidents()
                st.info("Showing cyber incidents")
                if not cyber_data.empty:
                    st.dataframe(cyber_data, use_container_width=True)
                else:
                    st.info("No data yet. Click 'Migrate Excel to DB' in sidebar to load data")
                metrics_data = cyber_data

            elif domain == "Data":
                with st.form("add_data"):
                    name = st.text_input("Asset Name")
                    asset_type = st.selectbox("Type", ["Database", "File", "API"])
                    classification = st.selectbox("Classification", ["Public", "Internal"])
                    owner = st.text_input("Owner", st.session_state.user)

                    if st.form_submit_button("Add"):
                        success = add_datasets_metadata(name, asset_type, classification, owner)
                        if success:
                            st.success("Added!")
                        else:
                            st.error("Something went wrong")

                filtered_data = get_datasets_metadata_db()
                if not filtered_data.empty:
                    st.dataframe(filtered_data, use_container_width=True)
                else:
                    st.info("No data assets found")

                metrics_data = filtered_data

            else:
                with st.form("add_it"):
                    title = st.text_input("Ticket Title")
                    category = st.selectbox("Category", ["Hardware", "Software", "Network"])
                    priority = st.selectbox("Priority", ["Low", "Medium", "High"])
                    if st.form_submit_button("Create Ticket"):
                        success = add_it_ticket(title, category, priority)
                        if success:
                            st.success("Added!")
                        else:
                            st.error("Something went wrong")

                filtered_data = get_it_tickets_db()
                if not filtered_data.empty:
                    st.dataframe(filtered_data, use_container_width=True)
                else:
                    st.info("No IT tickets found")

                metrics_data = filtered_data

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Total Items", len(metrics_data) if not metrics_data.empty else 0)

            with col2:
                if not metrics_data.empty:
                    if domain == "Cyber" and 'severity' in metrics_data.columns:
                        serious = len(metrics_data[metrics_data['severity'].isin(['High', 'Critical'])])
                        st.metric("Serious", serious)
                    elif domain == "IT" and 'priority' in metrics_data.columns:
                        high_priority = len(metrics_data[metrics_data['priority'] == 'High'])
                        st.metric("High Priority", high_priority)
                    elif domain == "Data" and 'classification' in metrics_data.columns:
                        confidential = len(metrics_data[metrics_data['classification'] == 'Internal'])
                        st.metric("Internal Assets", confidential)
                    else:
                        st.metric("Items", len(metrics_data))

            with col3:
                if not metrics_data.empty and 'status' in metrics_data.columns:
                    open_items = len(metrics_data[metrics_data['status'] == 'Open'])
                    st.metric("Open Items", open_items)
                else:
                    st.metric("Records", len(metrics_data) if not metrics_data.empty else 0)

        elif page == "Incidents":
            if st.session_state.role not in ["admin", "analyst"]:
                st.error("Access denied: Analyst or Admin role required")
                st.stop()
            st.title("Incident Management")

            incident_ids = []
            if not data.empty and "id" in data.columns:
                incident_ids = data["id"].tolist()

            with st.form("add_incident"):
                st.subheader("Add New incident")
                col1, col2, col3 = st.columns(3)
                with col1:
                    t = st.text_input("Incident Type*", placeholder="Phishing, Malware, etc.")
                with col2:
                    s = st.selectbox("Severity*", ["Low", "Medium", "High", "Critical"])
                with col3:
                    sts = st.selectbox("Status", ["Open", "In Progress", "Resolved"])
                d = st.text_area("Description*", placeholder="Enter incident details..")

                if st.form_submit_button("+Add Incident"):
                    success, result = add_incident_to_db(t, s, sts, d, st.session_state.user)
                    if success:
                        st.success(f"Incident #{result} added")
                        st.rerun()
                    else:
                        st.error(result)

            st.divider()

            if incident_ids:
                col1, col2 = st.columns(2)
                with col1:
                    with st.form("update_incident"):
                        st.subheader("Update Incident")
                        incident_id = st.selectbox("Select Incident", incident_ids, key="update")
                        incident = get_incident_by_id(incident_id)

                        if incident:
                            col1_form, col2_form = st.columns(2)
                            with col1_form:
                                new_t = st.text_input("Type", value=incident[2])
                                new_s = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"], index=["Low", "Medium", "High", "Critical"].index(incident[3]))
                            with col2_form:
                                new_sts = st.selectbox("Status", ["Open", "In Progress", "Resolved"], index=["Open", "In Progress", "Resolved"].index(incident[4]))
                                new_d = st.text_area("Description", value=incident[5])

                            if st.form_submit_button("Update Incident"):
                                success, msg = update_incident(incident_id, new_t, new_s, new_sts, new_d)
                                if success:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)

                with col2:
                    with st.form("delete_incident"):
                        st.subheader("Delete Incident")
                        del_incident_id = st.selectbox("Select Incident", incident_ids, key="delete")
                        incident = get_incident_by_id(del_incident_id)

                        if incident:
                            st.warning(f"Delete Incident #{del_incident_id}?")
                            st.write(f"**Type:** {incident[2]}")
                            st.write(f"**Severity:** {incident[3]}")
                            st.write(f"**Status:** {incident[4]}")

                            if st.form_submit_button("Confirm Delete"):
                                success, msg = remove_incident(del_incident_id)
                                if success:
                                    st.success(msg)
                                    st.rerun()
            else:
                st.info("No new incidents found")

        elif page == "Analytics":
            st.title(f"{domain} Analytics")

            if domain == "Cyber":
                analytics_data = get_incidents()
            elif domain == "Data":
                analytics_data = get_datasets_metadata_db()
            else:  # IT domain
                analytics_data = get_it_tickets_db()

            # Metrics section
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Total Items", len(analytics_data) if not analytics_data.empty else 0)

            with col2:
                if not analytics_data.empty:
                    if domain == "Cyber" and 'severity' in analytics_data.columns:
                        serious = len(analytics_data[analytics_data['severity'].isin(['High', 'Critical'])])
                        st.metric("Serious", serious)
                    elif domain == "IT" and 'priority' in analytics_data.columns:
                        high_priority = len(analytics_data[analytics_data['priority'] == 'High'])
                        st.metric("High Priority", high_priority)
                    elif domain == "Data" and 'classification' in analytics_data.columns:
                        confidential = len(analytics_data[analytics_data['classification'] == 'Internal'])
                        st.metric("Internal Assets", confidential)
                    else:
                        st.metric("Items", len(analytics_data))
                else:
                    st.metric("Items", 0)

            with col3:
                if not analytics_data.empty and 'status' in analytics_data.columns:
                    open_items = len(analytics_data[analytics_data['status'] == 'Open'])
                    st.metric("Open Items", open_items)
                else:
                    st.metric("Records", len(analytics_data) if not analytics_data.empty else 0)

            # Check if we have data for charts
            if not analytics_data.empty:
                st.subheader("Data")
                st.dataframe(analytics_data, use_container_width=True)

                st.divider()
                st.subheader("Insights")

                good_chart_columns = []
                for col in analytics_data.columns:
                    col_lower = col.lower()

                    skip_keywords = ['id', '_id', 'date', 'time', 'created', 'updated', 'description', 'reported_by']

                    if domain == "Cyber":
                        if col_lower in ['incident_type', 'severity', 'status']:
                            good_chart_columns.append(col)
                            continue

                    if any(keyword in col_lower for keyword in skip_keywords):
                        continue

                    unique_count = len(analytics_data[col].dropna().unique())
                    if unique_count > 20 and analytics_data[col].dtype != 'object':
                        continue

                    good_chart_columns.append(col)

                if len(good_chart_columns) >= 2:
                    chart_col1, chart_col2 = st.columns(2)

                    with chart_col1:
                        col1 = good_chart_columns[0]
                        if analytics_data[col1].dtype == 'object':
                            chart_data = analytics_data[col1].value_counts().head(10)
                            st.subheader(f"by {col1}")
                            st.bar_chart(chart_data)
                        else:
                            st.subheader(f"{col1} Distribution")
                            st.line_chart(analytics_data[col1].value_counts().sort_index())

                    with chart_col2:
                        if len(good_chart_columns) > 1:
                            col2 = good_chart_columns[1]
                            if analytics_data[col2].dtype == 'object':
                                chart_data = analytics_data[col2].value_counts().head(10)
                                st.subheader(f"by {col2}")
                                st.bar_chart(chart_data)
                            else:
                                st.subheader(f"{col2} Over Records")
                                st.area_chart(analytics_data[col2])
                        else:
                            st.info("Only one chart column found")

                elif len(good_chart_columns) == 1:
                    col1 = good_chart_columns[0]
                    st.subheader(f"{col1} Analysis")

                    if analytics_data[col1].dtype == 'object':
                        chart_data = analytics_data[col1].value_counts().head(15)
                        st.bar_chart(chart_data)

                        st.write("**Top Values:**")
                        for value, count in chart_data.items():
                            st.write(f"• **{value}**: {count} records")

                    else:
                        if analytics_data[col1].dtype in ['int64', 'float64']:
                            st.metric("Average", f"{analytics_data[col1].mean():.1f}")
                            st.metric("Min", f"{analytics_data[col1].min():.0f}")
                            st.metric("Max", f"{analytics_data[col1].max():.0f}")
                        st.line_chart(analytics_data[col1])
                else:
                    st.info("No suitable columns for automatic charts")
                    st.write("**Column Summary:**")
                    for col in analytics_data.columns[:5]:
                        st.write(
                            f"• `{col}`: {analytics_data[col].dtype}, {len(analytics_data[col].dropna().unique())} unique values")

            else:
                st.info(f"No data available for {domain} analysis")
                st.write("Click **'Migrate Excel to DB'** in the sidebar to load your data")

        elif page == "Admin":
            if st.session_state.role != "admin":
                st.error("Access denied: Admin role required")
                st.stop()

            st.title("Admin Tools")

            users_data = get_all_users()
            st.subheader("User Management")
            st.dataframe(users_data, use_container_width=True)

            if len(users_data) > 0:
                col1, col2 = st.columns(2)

                with col1:
                    st.write("**Update User Role**")
                    user_id = st.selectbox("Select User", users_data['id'].tolist(), key="user_update")
                    current_role = users_data[users_data['id'] == user_id]['role'].iloc[0]
                    new_role = st.selectbox("New Role", ["user", "analyst", "admin"],
                                            index=["user", "analyst", "admin"].index(current_role))

                    if st.button("Update Role"):
                        success, msg = update_user_role(user_id, new_role)
                        if success:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

                with col2:
                    st.write("**Delete User**")
                    available_users = users_data[users_data['username'] != st.session_state.user]
                    if len(available_users) > 0:
                        user_to_delete = st.selectbox("User to Delete", available_users['id'].tolist(), key="user_del")

                        if st.button("Delete User"):
                            success, msg = delete_user(user_to_delete)
                            if success:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
                    else:
                        st.info("No other users to delete")

        st.sidebar.divider()
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.role = None
            st.rerun()


if __name__ == "__main__":
    main()