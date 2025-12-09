from .db import connect_database

class ITTicket:
    """Represents an IT operations ticket in the platform."""

    def insert_ticket(self, ticket_id, priority, status, category, subject, description, created_date, assigned_to):
        """insert new IT ticket"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO it_tickets (ticket_id, priority, status, category, subject, description, created_date, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, priority, status, category, subject, description, created_date, assigned_to)
        )
        conn.commit()
        ticket_db_id = cursor.lastrowid
        conn.close()
        return ticket_db_id

    def get_all_tickets(self):
        """get all tickets"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM it_tickets ORDER BY id DESC")
        tickets = cursor.fetchall()
        conn.close()
        return tickets

