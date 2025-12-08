from models.dataset import Dataset
from database.db import connect_database

class DatasetManager:
    """manages datasets objects and database operations"""
    def create_dataset(self, name: str, source: str, size_bytes: int = None, rows: int = None, category: str = None) -> Dataset:
        """
        Insert new dataset and return Dataset object.

        Args:
            name: Dataset name
            source: Data source
            size_bytes: Size in bytes (required)
            rows: Number of rows (required)
            category: Optional category
            """
        if size_bytes is None or rows is None:
            raise ValueError("size_bytes and rows are required")
        conn = connect_database()
        cursor = conn.cursor()

        #insert info into database
        cursor.execute(
            """INSERT INTO datasets_metadata 
                    (dataset_name, source, size_bytes, rows, category) 
                    VALUES (?, ?, ?, ?, ?)""",
         (name, source, size_bytes, rows, category)
        )
        conn.commit()
        dataset_id = cursor.lastrowid
        conn.close()

        return Dataset(
            dataset_id=dataset_id,
            name=name,
            size_bytes=size_bytes,
            rows=rows,
            source=source
        )

    def get_dataset_by_id(self, dataset_id: int) -> Dataset:
        """retrieve dataset from database"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, dataset_name, size_bytes, rows, source 
                           FROM datasets_metadata WHERE id = ?""",
            (dataset_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if row and row["size_bytes"] is not None and row["rows"] is not None:
            return Dataset(
                dataset_id=row['id'],
                name=row['dataset_name'],
                size_bytes=row['size_bytes'],
                rows=row['rows'],
                source=row['source'] or "Unknown"
                 )
        return None

    def get_all_datasets(self):
        """get all datasets as list of dataset objects"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, dataset_name, size_bytes, rows, source 
               FROM datasets_metadata 
               WHERE size_bytes IS NOT NULL AND rows IS NOT NULL
               ORDER BY id DESC"""
        )
        rows = cursor.fetchall()
        conn.close()

        datasets = []
        for row in rows:
            dataset = Dataset(
                dataset_id=row['id'],
                name=row['dataset_name'],
                size_bytes=row['size_bytes'],
                rows=row['rows'],
                source=row['source'] or "Unknown"
            )
            datasets.append(dataset)
        return datasets

    def get_large_datasets(self):
        """get large dataset from database"""
        all_datasets = self.get_all_datasets()
        return [dataset for dataset in all_datasets if dataset.is_large()]

    def update_dataset(self, dataset_id: int, **kwargs):
        """update dataset from database"""
        allowed_fields = ["name", "source", "size_bytes", "rows", "category"]
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                db_column = "dataset_name" if key == "name" else key
                updates.append(f"{db_column} = ?")
                values.append(value)

        if not updates:
            return False

        values.append(dataset_id)
        conn = connect_database()
        cursor = conn.cursor()
        query = f"UPDATE datasets_metadata SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, values)
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    def delete_dataset(self, dataset_id: int) -> bool:
        """delete dataset from database"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM datasets_metadata WHERE id = ?",
            (dataset_id,)
        )
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    def get_dataset_status(self):
        """get dataset status from database"""
        datasets = self.get_all_datasets()

        if not datasets:
            return {
                "total_datasets": 0,
                "total_size_mb": 0,
                "total_rows": 0,
                "large_datasets": 0
            }

        stats = {
            "total_datasets": len(datasets),
            "total_size_mb": sum(d.calculate_size_mb() for d in datasets),
            "total_rows": sum(d.get_rows() for d in datasets),
            "large_datasets": len([d for d in datasets if d.is_large()])
        }
        return stats

