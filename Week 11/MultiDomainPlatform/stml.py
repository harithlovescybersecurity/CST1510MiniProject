import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import bcrypt
import os

# Page setup
st.set_page_config(page_title="Security App", layout="wide")

#intialize the session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

#models
class Database:
    """Database connection manager"""
    def __init__(self):
        self.db_path = "DATA/intelligence.db"
        self.init_db()

    def get_conn(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        conn = self.get_conn()
        cursor = conn.cursor()

        #create tables
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
        self.create_admin()

    def create_admin(self):
        conn = self.get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            pw_hash = bcrypt.hashpw("admin123".encode("utf-8"), bcrypt.gensalt())
            cursor.execute( "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", pw_hash.decode("utf-8"), "admin"))
            conn.commit()
        conn.close()

class UserManager:
    """"handles user authentication and management"""
    def __init__(self,db):
        self.db = db

    def check_login(self,username,password):
        """authenticate user"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        #checks if the user is there and password matches
        if user and bcrypt.checkpw(password.encode("utf-8"), user[0].encode("utf-8")):
            return True, user[1]
        return False, None

    def create_user(self,username,password, role="user"):
        """register a new user"""
        #validation
        if not username or ' ' in username or not username.isalnum():
            return False, "Username: letters/numbers not allowed"

        #password length
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        #must contain atleast one uppercase
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        #must contain atleast one lowercase
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        #must contain atleast one digit
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        #check digit
        special = "!@#$%^&*"
        if not any(c in special for c in password):
            return False, "Password must contain at least one special character"

        conn = self.db.get_conn()
        cursor = conn.cursor()

        if cursor.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone():
            conn.close()
            return False, "Username already exists"

        #hash the password
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, pw_hash.decode("utf-8"), role))
        conn.commit()
        conn.close()
        return True, "User created"


    def get_all_users(self):
        """get all users"""
        try:
            conn = self.db.get_conn()
            df = pd.read_sql("SELECT id, username, role FROM users", conn)
            conn.close()
            return df
        except Exception as e:
            print(f"Error getting users: {e}")
            return pd.DataFrame()

    def update_user_role(self, user_id, new_role):
        """update user role"""
        if new_role not in ["user", "analyst", "admin"]:
            return False, "Invalid role"

        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        return True, "Role updated"

    def delete_user(self, user_id):
        """delete user"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True, "User deleted"

class CyberIncidentManager:
    """"handles cyber incident creation"""

    def __init__(self,db):
        self.db = db

    def get_incidents(self):
        """get all incidents"""
        try:
            conn = self.db.get_conn()
            cursor = conn.cursor()

            #get all data
            cursor.execute("SELECT * FROM cyber_incidents")
            rows = cursor.fetchall()

            #get column names
            cursor.execute("PRAGMA table_info(cyber_incidents)")
            columns_info = cursor.fetchall()
            columns = [col[1] for col in columns_info]
            conn.close()

            if rows:
                df = pd.DataFrame(rows, columns=columns)
                return df
            else:
                return pd.DataFrame()
        except Exception as e:
            st.error(f"Error loading incidents: {str(e)[:100]}")
            return pd.DataFrame()

    def get_incident_by_id(self, incident_id):
        """get incident by id"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cyber_incidents WHERE id = ?", (incident_id,))
        incident = cursor.fetchone()
        conn.close()
        return incident

    def add_incident_to_db(self, incident_type, severity, status, description, reported_by):
        """add incident to database"""
        if not incident_type or not description:
            return False, "Required fields are missing"

        conn = self.db.get_conn()
        cursor = conn.cursor()

        #insert a new incident
        cursor.execute( "INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), incident_type, severity, status, description, reported_by))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()
        return True, new_id

    def update_incident(self, incident_id, incident_type, severity, status, description):
        """update incident"""
        if not incident_type or not description:
            return False, "Required fields are missing"
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE cyber_incidents SET incident_type = ?, severity = ?, status = ?, description = ? WHERE id = ?",
            (incident_type, severity, status, description, incident_id)
        )
        conn.commit()
        conn.close()
        return True, "Incident updated"

    def update_status(self, incident_id, status):
        """update status"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute("UPDATE cyber_incidents SET status = ? WHERE id = ?", (status, incident_id))
        conn.commit()
        conn.close()
        return True, "Status updated"

    def remove_incident(self, incident_id):
        """remove incident"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()
        return True, "Deleted"

class ITTicketManager:
    """"handles ticket creation"""
    def __init__(self,db):
        self.db = db

    def get_it_tickets(self):
        """get all tickets"""
        try:
            conn = self.db.get_conn()
            df = pd.read_sql("SELECT * FROM it_tickets", conn)
            conn.close()
            return df
        except Exception as e:
            print(f"Error getting IT tickets: {e}")
            return pd.DataFrame()

    def add_it_ticket(self, title, category, priority):
        """add ticket"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute( "INSERT INTO it_tickets (title, category, priority, status) VALUES (?, ?, ?, ?)",
            (title, category, priority, "Open"))
        conn.commit()
        conn.close()
        return True

class DatasetManager:
    """"handles dataset creation"""
    def __init__(self,db):
        self.db = db

    def get_datasets_metadata_db(self):
        """get all datasets metadata"""
        try:
            conn = self.db.get_conn()
            df = pd.read_sql("SELECT * FROM datasets_metadata", conn)
            conn.close()
            return df
        except Exception as e:
            print(f"Error getting datasets: {e}")
            return pd.DataFrame()

    def add_datasets_metadata(self, name, asset_type, classification, owner):
        """add datasets metadata"""
        conn = self.db.get_conn()
        cursor = conn.cursor()
        cursor.execute( "INSERT INTO datasets_metadata (name, asset_type, classification, owner) VALUES (?, ?, ?, ?)",
            (name, asset_type, classification, owner))
        conn.commit()
        conn.close()
        return True

class ExcelDataLoader:
    """"handles excel data loader"""
    def __init__(self):
        pass

    def get_excel_data(self, file_path):
        """get excel data"""
        try:
            if os.path.exists(file_path):
                df = pd.read_excel(file_path)
                return df
            else:
                return pd.DataFrame()
        except Exception as e:
            st.error(f"Error reading {file_path}: {str(e)[:100]}")
            return pd.DataFrame()

    def get_cyber_excel_data(self):
        """get cyber excel data"""
        return self.get_excel_data("DATA/cyber_incidents.xlsx")

    def get_it_tickets_excel(self):
        """get IT tickets excel"""
        return self.get_excel_data("DATA/it_tickets.xlsx")

    def get_datasets_metadata(self):
        """get datasets metadata"""
        return self.get_excel_data("DATA/datasets_metadata.xlsx")

class DataMigration:
    """"handles data migration"""
    def __init__(self,db, excel_loader):
        self.db = db
        self.excel_loader = excel_loader

    def migrate_all_data(self):
        """migrate all data"""
        conn = self.db.get_conn()
        cyber_df = self.excel_loader.get_cyber_excel_data()
        if not cyber_df.empty:
            if 'timestamp' in cyber_df.columns:
                cyber_df = cyber_df.rename(columns={'timestamp': 'date'})
            if 'category' in cyber_df.columns:
                cyber_df = cyber_df.rename(columns={'category': 'incident_type'})

            if "incident_id" in cyber_df.columns:
                cyber_df = cyber_df.drop(columns=['incident_id'])

            if 'reported_by' not in cyber_df.columns:
                cyber_df['reported_by'] = 'admin'

            correct_order = ['date', 'incident_type', 'severity', 'status', 'description', 'reported_by']
            cyber_df = cyber_df[correct_order]

            cyber_df.to_sql('cyber_incidents', conn, if_exists='replace', index=False)
            st.success(f"Migrated {len(cyber_df)} cyber incidents")
        else:
            st.error("No cyber incidents found")
            conn.close()
            return False

        datasets_df = self.excel_loader.get_datasets_metadata()
        if not datasets_df.empty:
            datasets_df.to_sql('datasets_metadata', conn, if_exists='replace', index=False)
            st.success(f"Migrated {len(datasets_df)} data assets")

        it_df = self.excel_loader.get_it_tickets_excel()
        if not it_df.empty:
            it_df.to_sql('it_tickets', conn, if_exists='replace', index=False)
            st.success(f"Migrated {len(it_df)} IT tickets")
        conn.close()
        st.success("Data migration complete")
        return True

#main application
def main():
    """main function"""
    db = Database()
    user_manager = UserManager(db)
    cyber_manager = CyberIncidentManager(db)
    it_manager = ITTicketManager(db)
    dataset_manager = DatasetManager(db)
    excel_loader = ExcelDataLoader()
    data_migration = DataMigration(db, excel_loader)

    #login page
    if not st.session_state.logged_in:
        st.title("🔐 Login")
        tab1, tab2 = st.tabs(["Login", "Register"])

        #login tabs
        with tab1:
            with st.form("login"):
                u = st.text_input("Username")
                p = st.text_input("Password", type="password")

                if st.form_submit_button("Login"):
                    if u and p:
                        success, role = user_manager.check_login(u, p)
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.user = u
                            st.session_state.role = role
                            st.success("Logged in successfully")
                            st.rerun()
                        else:
                            st.error("Login failed")
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
                        st.error("Passwords do not match")
                    else:
                        success, msg = user_manager.create_user(new_u, new_p, role)
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
                data_migration.migrate_all_data()

        domain = st.sidebar.selectbox("Domain", ["Cyber", "Data", "IT"])
        page = st.sidebar.radio("Go to", ["Dashboard", "Incidents", "Analytics", "Admin"])

        st.sidebar.divider()
        st.sidebar.subheader("AI Assistant")
        if st.sidebar.button("Gemini Interactive Chat"):
            st.switch_page("pages/AIAssistant.py")

        data = cyber_manager.get_incidents()

        #dashboard
        if page == "Dashboard":
            st.title(f"{domain} Dashboard")

            #cyber domain
            if domain == "Cyber":
                cyber_data = cyber_manager.get_incidents()
                st.info("Showing cyber incidents")

                if not cyber_data.empty:
                    st.dataframe(cyber_data, use_container_width=True)
                else:
                    st.info("No data yet. Click 'Migrate Excel to DB' in sidebar to load data")

                metrics_data = cyber_data

            #data domain
            elif domain == "Data":
                with st.form("add_data"):
                    name = st.text_input("Asset Name")
                    asset_type = st.selectbox("Asset Type", ["Database", "File", "API"])
                    classification = st.selectbox("Classification", ["Public", "Internal"])
                    owner = st.text_input("Owner", st.session_state.user)

                    if st.form_submit_button("Add"):
                        if dataset_manager.add_datasets_metadata(name, asset_type, classification, owner):
                            st.success("Added")
                            st.rerun()
                        else:
                            st.error("Failed to add")

                filtered_data = dataset_manager.get_datasets_metadata_db()
                if not filtered_data.empty:
                    st.dataframe(filtered_data, use_container_width=True)
                else:
                    st.info("No data found")
                metrics_data = filtered_data

            #IT domain
            else:
                with st.form("add_it"):
                    title = st.text_input("Ticket Title")
                    category = st.selectbox("Category", ["Hardware", "Software", "Network"])
                    priority = st.selectbox("Priority", ["Low", "Medium", "High"])

                    if st.form_submit_button("Create Ticket"):
                        if it_manager.add_it_ticket(title, category, priority):
                            st.success("Added!")
                            st.rerun()
                        else:
                            st.error("Something went wrong")

                #displays IT tickets
                filtered_data = it_manager.get_it_tickets()
                if not filtered_data.empty:
                    st.dataframe(filtered_data, use_container_width=True)
                else:
                    st.info("No IT tickets found")
                metrics_data = filtered_data

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Total Items", len(metrics_data) if not metrics_data.empty else 0)

            #domain specific data
            with col2:
                if not metrics_data.empty:
                    if domain == "Cyber" and 'severity' in metrics_data.columns:
                        #counts serious incidents High or Critical
                        serious = len(metrics_data[metrics_data['severity'].isin(['High', 'Critical'])])
                        st.metric("Serious", serious)
                    elif domain == "IT" and 'priority' in metrics_data.columns:
                        #count high priority tickets
                        high_priority = len(metrics_data[metrics_data['priority'] == 'High'])
                        st.metric("High Priority", high_priority)
                    elif domain == "Data" and 'classification' in metrics_data.columns:
                        #count assets
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
            #authorization only analysts and admins
            if st.session_state.role not in ["admin", "analyst"]:
                st.error("Access denied: Analyst or Admin role required")
                st.stop()

            st.title("Incident Management")

            #get all incidents
            incident_ids = []
            if not data.empty and "id" in data.columns:
                incident_ids = data["id"].tolist()

            with st.form("add_incident"):
                st.subheader("Add New Incident")
                col1, col2, col3 = st.columns(3)
                with col1:
                    t = st.text_input("Incident Type*", placeholder="Phishing, Malware, etc.")
                with col2:
                    s = st.selectbox("Severity*", ["Low", "Medium", "High", "Critical"])
                with col3:
                    sts = st.selectbox("Status", ["Open", "In Progress", "Resolved"])
                d = st.text_area("Description*", placeholder="Enter incident details..")

                if st.form_submit_button("+Add Incident"):
                    success, result = cyber_manager.add_incident_to_db(t, s, sts, d, st.session_state.user)
                    if success:
                        st.success(f"Incident #{result} added")
                        st.rerun()
                    else:
                        st.error(result)

            st.divider()

            if incident_ids:
                col1, col2 = st.columns(2)

                # update Incident
                with col1:
                    with st.form("update_incident"):
                        st.subheader("Update Incident")
                        incident_id = st.selectbox("Select Incident", incident_ids, key="update")
                        incident_data = cyber_manager.get_incident_by_id(incident_id)

                        if incident_data:
                            col1_form, col2_form = st.columns(2)
                            with col1_form:
                                new_t = st.text_input("Type", value=incident_data[2])
                                new_s = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"],index=["Low", "Medium", "High", "Critical"].index(incident_data[3]))
                            with col2_form:
                                new_sts = st.selectbox("Status", ["Open", "In Progress", "Resolved"],index=["Open", "In Progress", "Resolved"].index(incident_data[4]))
                                new_d = st.text_area("Description", value=incident_data[5])

                            if st.form_submit_button("Update Incident"):
                                success, msg = cyber_manager.update_incident(incident_id, new_t, new_s, new_sts, new_d)
                                if success:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)

                #delete incident
                with col2:
                    with st.form("delete_incident"):
                        st.subheader("Delete Incident")
                        del_incident_id = st.selectbox("Select Incident", incident_ids, key="delete")
                        incident_data = cyber_manager.get_incident_by_id(del_incident_id)

                        if incident_data:
                            st.warning(f"Delete Incident #{del_incident_id}?")
                            st.write(f"**Type:** {incident_data[2]}")
                            st.write(f"**Severity:** {incident_data[3]}")
                            st.write(f"**Status:** {incident_data[4]}")

                            if st.form_submit_button("Confirm Delete"):
                                success, msg = cyber_manager.remove_incident(del_incident_id)
                                if success:
                                    st.success(msg)
                                    st.rerun()
            else:
                st.info("No incidents found")

        elif page == "Analytics":
            st.title(f"{domain} Analytics")

            #getting data based on selected domain
            if domain == "Cyber":
                analytics_data = cyber_manager.get_incidents()
            elif domain == "Data":
                analytics_data = dataset_manager.get_datasets_metadata_db()
            else:
                analytics_data = it_manager.get_it_tickets()

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

                #charts based on available columns
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
            #checks if user is admin
            if st.session_state.role != "admin":
                st.error("Access denied: Admin role required")
                st.stop()

            st.title("Admin Tools")

            #get all users
            users_data = user_manager.get_all_users()
            st.subheader("User Management")
            st.dataframe(users_data, use_container_width=True)

            if len(users_data) > 0:
                col1, col2 = st.columns(2)

                #update user role
                with col1:
                    st.write("**Update User Role**")
                    user_id = st.selectbox("Select User", users_data['id'].tolist(), key="user_update")
                    current_role = users_data[users_data['id'] == user_id]['role'].iloc[0]
                    new_role = st.selectbox("New Role", ["user", "analyst", "admin"],
                                            index=["user", "analyst", "admin"].index(current_role))

                    if st.button("Update Role"):
                        success, msg = user_manager.update_user_role(user_id, new_role)
                        if success:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

                #delete user
                with col2:
                    st.write("**Delete User**")
                    available_users = users_data[users_data['username'] != st.session_state.user]
                    if len(available_users) > 0:
                        user_to_delete = st.selectbox("User to Delete", available_users['id'].tolist(), key="user_del")

                        if st.button("Delete User"):
                            success, msg = user_manager.delete_user(user_to_delete)
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










