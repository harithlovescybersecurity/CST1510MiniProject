import pandas as pd
from apps.data.db import connect_database

def insert_incident(date, incident_type, severity, status, description, reported_by=None):
    """Insert new incident"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by) VALUES (?, ?, ?, ?, ?, ?)",
        (date, incident_type, severity, status, description, reported_by)
    )
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()
    return incident_id


def get_all_incidents(conn):
    """Get all incidents"""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(cyber_incidents)")
    columns = cursor.fetchall()

    column_names = [col[1] for col in columns]
    if 'id' in column_names:
        query = "SELECT * FROM cyber_incidents ORDER BY date DESC"
    else:
        query = "SELECT * FROM cyber_incidents"

    df = pd.read_sql_query(query, conn)
    return df

def update_incident_status(conn, date, incident_type, new_status):
    """Update incident by date and type"""
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cyber_incidents SET status = ? WHERE date = ? AND incident_type = ?",
        (new_status, date, incident_type)
    )
    conn.commit()
    return cursor.rowcount

def delete_incident(conn, date, incident_type):
    """Delete incident by date and type"""
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM cyber_incidents WHERE date = ? AND incident_type = ?",
        (date, incident_type)
    )
    conn.commit()
    return cursor.rowcount

def get_incidents_by_type_count(conn):
    """Count incidents by type"""
    query = """
    SELECT incident_type, COUNT(*) as count
    FROM cyber_incidents
    GROUP BY incident_type
    ORDER BY count DESC
    """
    df = pd.read_sql_query(query, conn)
    return df

def get_high_severity_by_status(conn):
    """Count high severity incidents by status"""
    query = """
    SELECT status, COUNT(*) as count
    FROM cyber_incidents
    WHERE severity = 'High'
    GROUP BY status
    ORDER BY count DESC
    """
    df = pd.read_sql_query(query, conn)
    return df

def get_incident_types_with_many_cases(conn, min_count=5):
    """Find incident types with more than min_count cases"""
    query = """
    SELECT incident_type, COUNT(*) as count
    FROM cyber_incidents
    GROUP BY incident_type
    HAVING COUNT(*) > ?
    ORDER BY count DESC
    """
    df = pd.read_sql_query(query, conn, params=(min_count,))
    return df