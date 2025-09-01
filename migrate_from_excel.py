#!/usr/bin/env python3
"""
One-time migration script to populate the database from Excel file.
This script reads "Aurum - Employee List.xlsx" and creates departments and users.
"""

import sqlite3
import pandas as pd
import hashlib
import os

def hash_password(password):
    """Hash a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def migration():
    # Database connection
    db_path = './prompt_manager.db'
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} not found!")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("Step 1: Dropping existing tables and creating new schema...")
        
        # Drop existing tables
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS departments")
        
        # Create departments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        
        # Create users table with password_hash column
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                department_id INTEGER,
                FOREIGN KEY (department_id) REFERENCES departments (id)
            )
        """)
        
        print("✓ Database schema created successfully")
        
        print("Step 2: Reading Excel file...")
        
        # Read the Excel file
   
        
        # Read first four columns: first_name, surname, email, department

        # Step 1: Define the lists
        first_name = ['Alice', 'Bob']
        surname = ['S', 'W']
        email = ['test1@aurum.com', 'test2@aurum.com']
        department = ['Research', 'Finance']

        # Step 2: Put them into a dictionary
        data = {
            "first_name": first_name,
            "surname": surname,
            "Email": email,
            "department": department
        }

        # Step 3: Create the DataFrame
        df = pd.DataFrame(data)


        
        print(f"✓ Read {len(df)} rows from Excel file")
        
        print("Step 3: Processing and inserting data...")
        
        departments_added = set()
        users_added = 0
        
        for index, row in df.iterrows():
            try:
                # Clean data
                first_name = str(row['first_name']).strip()
                surname = str(row['surname']).strip()
                email = str(row['Email']).strip().lower()
                department = str(row['department']).strip()
                
                # Skip rows with missing essential data
                if pd.isna(row['Email']) or pd.isna(row['department']) or not email:
                    print(f"Skipping row {index + 1}: Missing email or department")
                    continue
                
                # Insert department (using INSERT OR IGNORE for duplicates)
                cursor.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (department,))
                
                # Get department ID
                cursor.execute("SELECT id FROM departments WHERE name = ?", (department,))
                department_id = cursor.fetchone()[0]
                
                if department not in departments_added:
                    print(f"  Added department: {department}")
                    departments_added.add(department)
                
                # Create full name
                full_name = f"{first_name} {surname}".strip()
                
                # Insert user (password_hash will be NULL initially)
                cursor.execute("""
                    INSERT OR IGNORE INTO users (name, email, password_hash, department_id) 
                    VALUES (?, ?, NULL, ?)
                """, (full_name, email, department_id))
                
                if cursor.rowcount > 0:
                    users_added += 1
                    print(f"  Added user: {full_name} ({email}) - {department}")
                
            except Exception as e:
                print(f"Error processing row {index + 1}: {e}")
                continue
        
        # Commit all changes
        conn.commit()
        
        print(f"\nStep 4: Migration completed successfully!")
        print(f"✓ Added {len(departments_added)} departments")
        print(f"✓ Added {users_added} users")
        
        # Display summary
        cursor.execute("SELECT COUNT(*) FROM departments")
        dept_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        print(f"\nDatabase Summary:")
        print(f"- Total departments: {dept_count}")
        print(f"- Total users: {user_count}")
        
        # Show sample data
        print(f"\nSample departments:")
        cursor.execute("SELECT name FROM departments LIMIT 5")
        for dept in cursor.fetchall():
            print(f"  - {dept[0]}")
        
        print(f"\nSample users:")
        cursor.execute("""
            SELECT u.name, u.email, d.name as department 
            FROM users u 
            LEFT JOIN departments d ON u.department_id = d.id 
            LIMIT 5
        """)
        for user in cursor.fetchall():
            print(f"  - {user[0]} ({user[1]}) - {user[2]}")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    
    finally:
        conn.close()
        print(f"\nMigration script completed. Database connection closed.")

