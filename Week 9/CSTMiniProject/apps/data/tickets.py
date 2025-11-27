from app.data.db import connect_database

def insert_ticket(ticket_id, priority, status, category, subject, description, created_date, assigned_to):
    """Insert new IT ticket"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO it_tickets (ticket_id, priority, status, category, subject, description, created_date, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ticket_id, priority, status, category, subject, description,created_date, assigned_to)
    )
    conn.commit()
    ticket_db_id = cursor.lastrowid
    conn.close()
    return ticket_db_id

def get_all_tickets():
    """Get all tickets"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets ORDER BY id DESC")
    tickets = cursor.fetchall()
    conn.close()
    return tickets
