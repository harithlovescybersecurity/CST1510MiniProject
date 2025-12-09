import pandas as pd
from pathlib import Path

def load_excel_to_table(conn, excel_path, table_name):
    """Load Excel file into database table"""
    if not Path(excel_path).exists():
        print(f"Excel file not found: {excel_path}")
        return 0

    df = pd.read_excel(excel_path)
    row_count = len(df)
    df.to_sql(
        name=table_name,
        con=conn,
        if_exists='append',
        index=False
    )
    print(f"Loaded {row_count} rows from {Path(excel_path).name} into {table_name} table")
    return row_count

def load_all_excel_data(conn):
    """Load all Excel files into their respective tables"""
    total_rows = 0

    excel_mappings = [
        ("DATA/cyber_incidents.xlsx", "cyber_incidents"),
        ("DATA/datasets_metadata.xlsx", "datasets_metadata"),
        ("DATA/it_tickets.xlsx", "it_tickets")
    ]

    for excel_path, table_name in excel_mappings:
        rows = load_excel_to_table(conn, excel_path, table_name)
        total_rows += rows

    return total_rows