import pandas as pd
from .db import connect_database

class Incident:
    """Manages cyber incident operations"""

    def insert_incident(self, date, incident_type, severity, status, description, reported_by=None):
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

    def get_all_incidents(self, conn):
        """Get all incidents"""
        df = pd.read_sql_query(
            "SELECT * FROM cyber_incidents ORDER BY id DESC", conn
        )
        return df

    def update_incident_status(self, conn, incident_id, new_status):
        """Update the incident status"""
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE cyber_incidents SET status = ? WHERE id = ?",
            (new_status, incident_id)
        )
        conn.commit()
        return cursor.rowcount

    def delete_incident(self, conn, incident_id):
        """Delete incident"""
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM cyber_incidents WHERE id = ?",
            (incident_id,)
        )
        conn.commit()
        return cursor.rowcount

    def get_incidents_by_type_count(self, conn):
        """Count incidents by type"""
        query = """
        SELECT incident_type, COUNT(*) as count
        FROM cyber_incidents
        GROUP BY incident_type
        ORDER BY count DESC
        """
        df = pd.read_sql_query(query, conn)
        return df

    def get_high_severity_by_status(self, conn):
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

    def get_incident_types_with_many_cases(self, conn, min_count=5):
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