from app.data.db import connect_database

def insert_dataset(dataset_name, category, source, last_updated, record_count, file_size_mb):
    """Insert new dataset"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO datasets_metadata (dataset_name, category, source, last_updated, record_count, file_size_mb) VALUES (?, ?, ?, ?, ?, ?)",
        (dataset_name, category, source, last_updated, record_count, file_size_mb)
    )
    conn.commit()
    dataset_id = cursor.lastrowid
    conn.close()
    return dataset_id

def get_all_datasets():
    """Get all datasets"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM datasets_metadata ORDER BY id DESC")
    datasets = cursor.fetchall()
    conn.close()
    return datasets