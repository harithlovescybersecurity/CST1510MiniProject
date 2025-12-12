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
        self.db_path = "database/platform.db"
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

    def login(self,username,password):
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
        if not username or not password or len(password) < 8 or ' ' in username or not username.isalnum():
            return False, "Invalid input"
        conn = self.db.get_conn()
        cursor = conn.cursor()

        #check if the username alr exists
        if cursor.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone():
            conn.close()
            return False, "Username already exists"

        #hashing the pass and save user
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
                


