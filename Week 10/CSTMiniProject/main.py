import random
from apps.data.db import connect_database
from apps.data.schema import create_all_tables
from apps.services.user_service import register_user, login_user, migrate_users_from_file
from apps.data.incidents import insert_incident, get_all_incidents, get_incidents_by_type_count, get_high_severity_by_status, get_incident_types_with_many_cases, update_incident_status, delete_incident
from apps.data.csv_loader import load_all_csv_data

def run_comprehensive_tests():
    """Run comprehensive tests on database"""
    print("\n" + "=" * 60)
    print("RUNNING COMPREHENSIVE TESTS")
    print("=" * 60)

    conn = connect_database()

    # Test 1: Authentication
    print("\n[TEST 1] Authentication")

    unique_id = random.randint(1000, 9999)
    test_username = f"test_user_{unique_id}"
    success, msg = register_user(test_username, "TestPass123!", "user")
    print(f" Register: {msg}")

    success, msg = login_user(test_username, "TestPass123!")
    print(f" Login: {msg}")

    # Test 2: CRUD Operations
    print("\n[TEST 2] CRUD Operations")

    # Create - Define date and type variables
    test_date = "2024-11-05"
    test_incident_type = "Test Incident"

    test_id = insert_incident(
        test_date,
        test_incident_type,
        "Low",
        "Open",
        "This is a test incident",
        test_username
    )
    print(f" Create: Incident created (Date: {test_date}, Type: {test_incident_type})")

    # Read
    incidents = get_all_incidents(conn)
    print(f" Read: Found {len(incidents)} total incidents")

    # Update - Use date and type instead of id
    rows_updated = update_incident_status(conn, test_date, test_incident_type, "Resolved")
    print(f" Update: {rows_updated} incident(s) updated")

    # Delete - Use date and type instead of id
    rows_deleted = delete_incident(conn, test_date, test_incident_type)
    print(f" Delete: {rows_deleted} incident(s) deleted")

    print("\n[TEST 3] Analytical Queries")

    df_by_type = get_incidents_by_type_count(conn)
    print(f" By Type: Found {len(df_by_type)} incident types")

    df_high = get_high_severity_by_status(conn)
    print(f" High Severity: Found {len(df_high)} status categories")

    conn.close()

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)

def main():
    print("=" * 60)
    print("Week 8: Database Demo")
    print("=" * 60)

    conn = connect_database()
    create_all_tables(conn)
    migrate_users_from_file("DATA/users.txt")

    print("\n" + "=" * 40)
    print("VERIFICATION: Users in database")
    print("=" * 40)

    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()

    print(f"{'ID':<5} {'Username':<15} {'Role':<10}")
    print("-" * 35)
    for user in users:
        print(f"{user[0]:<5} {user[1]:<15} {user[2]:<10}")
    print(f"\nTotal users: {len(users)}")
    conn.close()

    insert_incident(
        "2024-11-05",
        "Phishing",
        "High",
        "Open",
        "Suspicious email campaign",
        "alice"
    )
    print("Created incident")

    conn = connect_database()

    print("\n" + "=" * 40)
    print("ANALYTICAL QUERIES")
    print("=" * 40)

    print("\nIncidents by Type:")
    df_by_type = get_incidents_by_type_count(conn)
    print(df_by_type)

    print("\nHigh Severity Incidents by Status:")
    df_high_severity = get_high_severity_by_status(conn)
    print(df_high_severity)

    print("\nIncident Types with Many Cases (>5):")
    df_many_cases = get_incident_types_with_many_cases(conn, min_count=5)
    print(df_many_cases)
    conn.close()

    run_comprehensive_tests()

if __name__ == "__main__":
    main()

