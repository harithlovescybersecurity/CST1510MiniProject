import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import bcrypt

#page set up
st.set_page_config(page_title="Security App", layout="wide")
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

#gettingg the database functions
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
    conn.commit()
    conn.close()

def check_login(u,p):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, role FROM users WHERE username=?",(u,))
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
        return False, "Username already exits"
    pw_hash = bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (u, pw_hash.decode("utf-8"), role))
    conn.commit()
    conn.close()
    return True, "User created"

#implementing the CRUD functions
def get_incidents():
    conn = get_db()
    df = pd.read_sql_query("SELECT * FROM cyber_incidents ORDER BY id DESC", conn)
    conn.close()
    return df

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
    conn= get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by) VALUES (?, ?, ?, ?, ?, ?)", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), t, s, sts, d, u))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return True, new_id

def update_incident(incident_id, incident_type, severity, status,description):
    if not incident_type or not description:
        return False, "Required fields are missing"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE cyber_incidents SET incident_type = ?, severity = ?, status = ?, description = ? WHERE id = ?", (incident_type, severity, status, description, incident_id))
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







