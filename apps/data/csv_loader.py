import pandas as pd
from pathlib import Path

def load_csv_to_table(conn, csv_path, table_name):
    """Load CSV file into database table"""
    if not Path(csv_path).exists():
        print(f"CSV file not found: {csv_path}")
        return 0

    df = pd.read_csv(csv_path)
    row_count = len(df)
    df.to_sql(
        name=table_name,
        con=conn,
        if_exists='append',
        index=False
    )
    print(f"Loaded {row_count} rows from {Path(csv_path).name} into {table_name} table")
    return row_count

def load_all_csv_data(conn):
    """Load all CSV files into their respective tables"""
    total_rows = 0

    csv_mappings = [
        ("DATA/cyber_incidents.csv", "cyber_incidents"),
        ("DATA/datasets_metadata.csv", "datasets_metadata"),
        ("DATA/it_tickets.csv", "it_tickets")
    ]

    for csv_path, table_name in csv_mappings:
        rows = load_csv_to_table(conn, csv_path, table_name)
        total_rows += rows

    return total_rows