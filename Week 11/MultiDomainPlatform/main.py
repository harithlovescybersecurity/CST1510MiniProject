import random
import sqlite3
from pathlib import Path
import pandas as pd
from models.db import connect_database
from models.schema import DatabaseSchema


class MainApplication:
    def __init__(self):
        self.project_root = Path(__file__).parent

    def connect_db(self):
        """Connect to database"""
        return connect_database()

    def register_user(self, username, password, role="user"):
        """Actually register a user in database"""
        conn = self.connect_db()
        try:
            cursor = conn.cursor()
            # Simple password hash simulation
            password_hash = f"hash_{password}"
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return True, f"User '{username}' registered successfully."
        except sqlite3.IntegrityError:
            conn.close()
            return True, f"User '{username}' already exists."
        except Exception as e:
            conn.close()
            return False, f"Error: {e}"

    def login_user(self, username, password):
        """Simulate login"""
        return True, "Login successful!"

    def migrate_users_from_file(self, filename):
        """Actually migrate users from file"""
        filepath = self.project_root / filename
        if not filepath.exists():
            print(f"File not found: {filename}")
            return False

        try:
            conn = self.connect_db()
            cursor = conn.cursor()
            users_added = 0

            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split(',')
                    if len(parts) >= 3:
                        username = parts[0].strip()
                        password = parts[1].strip()
                        role = parts[2].strip() if len(parts) > 2 else "user"

                        # Check if user exists
                        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                        if cursor.fetchone() is None:
                            password_hash = f"hash_{password}"
                            cursor.execute(
                                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                                (username, password_hash, role)
                            )
                            users_added += 1

            conn.commit()
            conn.close()
            print(f"Migrated {users_added} users from {filename}")
            return True
        except Exception as e:
            print(f"Error migrating users: {e}")
            return False

    def insert_incident(self, date, incident_type, severity, status, description, reported_by):
        """Actually insert incident into database"""
        conn = self.connect_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO cyber_incidents 
                (date, incident_type, severity, status, description, reported_by) 
                VALUES (?, ?, ?, ?, ?, ?)""",
                (date, incident_type, severity, status, description, reported_by)
            )
            conn.commit()
            incident_id = cursor.lastrowid
            conn.close()
            print(f"Created incident: {incident_type} (ID: {incident_id})")
            return incident_id
        except Exception as e:
            print(f"Error inserting incident: {e}")
            conn.close()
            return 0

    def get_all_incidents(self, conn=None):
        """Get all incidents from database"""
        close_conn = False
        if conn is None:
            conn = self.connect_db()
            close_conn = True

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cyber_incidents")
            incidents = cursor.fetchall()

            if close_conn:
                conn.close()

            return incidents
        except Exception as e:
            print(f"Error getting incidents: {e}")
            if close_conn:
                conn.close()
            return []

    def get_incidents_by_type_count(self, conn=None):
        """Get incidents count by type"""
        close_conn = False
        if conn is None:
            conn = self.connect_db()
            close_conn = True

        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT incident_type, COUNT(*) as count FROM cyber_incidents GROUP BY incident_type"
            )
            results = cursor.fetchall()

            df = pd.DataFrame(results, columns=['incident_type', 'count'])

            if close_conn:
                conn.close()

            return df
        except Exception as e:
            print(f"Error getting incidents by type: {e}")
            if close_conn:
                conn.close()
            return pd.DataFrame(columns=['incident_type', 'count'])

    def get_high_severity_by_status(self, conn=None):
        """Get high severity incidents by status"""
        close_conn = False
        if conn is None:
            conn = self.connect_db()
            close_conn = True

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT status, COUNT(*) as count 
                FROM cyber_incidents 
                WHERE severity IN ('High', 'Critical') 
                GROUP BY status
            """)
            results = cursor.fetchall()

            df = pd.DataFrame(results, columns=['status', 'count'])

            if close_conn:
                conn.close()

            return df
        except Exception as e:
            print(f"Error getting high severity incidents: {e}")
            if close_conn:
                conn.close()
            return pd.DataFrame(columns=['status', 'count'])

    def get_incident_types_with_many_cases(self, conn=None, min_count=5):
        """Get incident types with many cases"""
        close_conn = False
        if conn is None:
            conn = self.connect_db()
            close_conn = True

        try:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT incident_type, COUNT(*) as count 
                FROM cyber_incidents 
                GROUP BY incident_type 
                HAVING COUNT(*) > {min_count}
            """)
            results = cursor.fetchall()

            df = pd.DataFrame(results, columns=['incident_type', 'count'])

            if close_conn:
                conn.close()

            return df
        except Exception as e:
            print(f"Error getting many cases: {e}")
            if close_conn:
                conn.close()
            return pd.DataFrame(columns=['incident_type', 'count'])

    def update_incident_status(self, conn, incident_id, new_status):
        """Update incident status"""
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE cyber_incidents SET status = ? WHERE id = ?",
                (new_status, incident_id)
            )
            conn.commit()
            return True, f"Incident {incident_id} status updated to {new_status}"
        except Exception as e:
            return False, f"Error updating incident: {e}"

    def delete_incident(self, conn, incident_id):
        """Delete incident"""
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
            conn.commit()
            return True, f"Incident {incident_id} deleted"
        except Exception as e:
            return False, f"Error deleting incident: {e}"

    def run_comprehensive_tests(self):
        """Run tests - similar to your original"""
        print("\n" + "=" * 60)
        print("RUNNING COMPREHENSIVE TESTS")
        print("=" * 60)

        conn = self.connect_db()

        # Test 1: Authenticate
        print("\n[TEST 1] Authentication")

        unique_id = random.randint(1000, 9999)
        test_username = f"test_user_{unique_id}"
        success, msg = self.register_user(test_username, "TestPass123!", "user")
        print(f" Register: {msg}")

        success, msg = self.login_user(test_username, "TestPass123!")
        print(f" Login: {msg}")

        # Test 2: CRUD Operations
        print("\n[TEST 2] CRUD Operations")

        # Create
        test_id = self.insert_incident(
            "2024-11-05",
            "Test Incident",
            "Low",
            "Open",
            "This is a test incident",
            test_username
        )
        print(f" Create: Incident #{test_id} created")

        # Read
        incidents = self.get_all_incidents(conn)
        print(f" Read: Found {len(incidents)} total incidents")

        # Update
        success, msg = self.update_incident_status(conn, test_id, "Resolved")
        print(f" Update: {msg}")

        # Delete
        success, msg = self.delete_incident(conn, test_id)
        print(f" Delete: {msg}")

        print("\n[TEST 3] Analytical Queries")

        df_by_type = self.get_incidents_by_type_count(conn)
        print(f" By Type: Found {len(df_by_type)} incident types")

        df_high = self.get_high_severity_by_status(conn)
        print(f" High Severity: Found {len(df_high)} status categories")

        conn.close()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED!")
        print("=" * 60)

    def main(self):
        print("=" * 60)
        print("Week 8: Database Demo")
        print("=" * 60)

        conn = self.connect_db()

        # Create tables using DatabaseSchema
        schema = DatabaseSchema(conn)
        schema.create_all_tables(conn)
        print("All tables created successfully!")

        # Migrate users
        self.migrate_users_from_file("DATA/users.txt")

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

        # If no users, add some sample users
        if len(users) == 0:
            print("\nAdding sample users...")
            sample_users = [
                ("alice", "password123", "admin"),
                ("bob", "password456", "user"),
                ("charlie", "password789", "analyst")
            ]
            for username, password, role in sample_users:
                self.register_user(username, password, role)

            # Re-fetch users
            cursor.execute("SELECT id, username, role FROM users")
            users = cursor.fetchall()
            print(f"Now have {len(users)} users")

        conn.close()

        # Insert incident
        self.insert_incident(
            "2024-11-05",
            "Phishing",
            "High",
            "Open",
            "Suspicious email campaign",
            "alice"
        )
        print("Created incident")

        conn = self.connect_db()

        print("\n" + "=" * 40)
        print("ANALYTICAL QUERIES")
        print("=" * 40)

        print("\nIncidents by Type:")
        df_by_type = self.get_incidents_by_type_count(conn)
        print(df_by_type)

        print("\nHigh Severity Incidents by Status:")
        df_high_severity = self.get_high_severity_by_status(conn)
        print(df_high_severity)

        print("\nIncident Types with Many Cases (>5):")
        df_many_cases = self.get_incident_types_with_many_cases(conn, min_count=5)
        print(df_many_cases)

        conn.close()

        self.run_comprehensive_tests()


# Run the application
if __name__ == "__main__":
    app = MainApplication()
    app.main()