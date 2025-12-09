from .db import connect_database

class Dataset:
    """manages dataset operations"""

    def insert_dataset(self, dataset_name, category, source, last_updated, record_count, file_size_mb):
        """insert new data set"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute( "INSERT INTO datasets_metadata (dataset_name, category, source, last_updated, record_count, file_size_mb) VALUES (?, ?, ?, ?, ?, ?)",
            (dataset_name, category, source, last_updated, record_count, file_size_mb)
        )
        conn.commit()
        dataset_id = cursor.lastrowid
        conn.close()
        return dataset_id

    def get_all_datasets(self):
        """get all datasets"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM datasets_metadata ORDER BY id DESC")
        datasets = cursor.fetchall()
        conn.close()
        return datasets