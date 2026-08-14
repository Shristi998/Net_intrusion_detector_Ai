import sqlite3

def fix_db():
    try:
        conn = sqlite3.connect('nids.db')
        conn.execute("UPDATE TRAFFIC_LOG SET classification='Normal' WHERE classification='Benign'")
        try:
            conn.execute("UPDATE ALERT SET classification='Normal' WHERE classification='Benign'")
        except sqlite3.OperationalError:
            pass # ALERT might not have classification column
        conn.commit()
        conn.close()
        print("Database updated!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    fix_db()
