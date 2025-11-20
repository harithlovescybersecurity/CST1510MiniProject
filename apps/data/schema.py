def create_users_table(conn):
    """Create users table"""
    cursor = conn.cursor()
    cursor.execute(""" CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user')
            """)
    conn.commit()
    print("✅ Users table created successfully!")

def create_cyber_incidents_table(conn):
    """Create cyber incidents table"""
    cursor = conn.cursor()
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS cyber_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            incident_type TEXT ,
            severity TEXT,
            status TEXT,
            description TEXT,
            reported_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    cursor.execute(create_table_sql)
    conn.commit()
    print("✅ Cyber incidents table created successfully!")

def create_datasets_metadata_table(conn):
    """Create datasets metadata table"""
    cursor = conn.cursor()
    create_table_sql = """
     CREATE TABLE IF NOT EXISTS datasets_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_name TEXT NOT NULL,
            category TEXT,
            source TEXT,
            last_updated TEXT,
            record_count INTEGER,
            file_size_mb REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     )
     """
    cursor.execute(create_table_sql)
    conn.commit()
    print("✅ Datasets metadata table created successfully!")

def create_it_tickets_table(conn):
    """ Create IT tickets table"""
    cursor = conn.cursor()
    create_table_sql = """ 
    CREATE TABLE IF NOT EXISTS it_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT UNIQUE NOT NULL,
            priority TEXT,
            status TEXT,
            category TEXT,
            subject TEXT NOT NULL,
            description TEXT,
            created_date TEXT,
            resolved_date TEXT,
            assigned_to TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    cursor.execute(create_table_sql)
    conn.commit()
    print("✅ IT tickets table created successfully!")

def create_all_tables(conn):
    """Create all tables"""
    create_users_table(conn)
    create_cyber_incidents_table(conn)
    create_datasets_metadata_table(conn)
    create_it_tickets_table(conn)
    print("All tables created successfully!")