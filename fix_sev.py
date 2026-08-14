import sqlite3

def get_sev(cls):
    if cls == "Normal" or cls == "Benign": return "Low"
    cls_lower = cls.lower()
    if 'dos' in cls_lower or 'infiltration' in cls_lower or 'botnet' in cls_lower: return 'Critical'
    if 'web' in cls_lower or 'brute' in cls_lower or 'sql' in cls_lower: return 'High'
    if 'scan' in cls_lower or 'recon' in cls_lower: return 'Medium'
    return 'High'

def fix_sev():
    try:
        conn = sqlite3.connect('nids.db')
        cursor = conn.cursor()
        
        # We need to update the severity in the ALERT table
        cursor.execute('''
            SELECT a.alert_id, t.classification
            FROM ALERT a
            JOIN TRAFFIC_LOG t ON a.log_id = t.log_id
        ''')
        rows = cursor.fetchall()
        for alert_id, classification in rows:
            sev = get_sev(classification)
            conn.execute("UPDATE ALERT SET severity_level=? WHERE alert_id=?", (sev, alert_id))
            
        conn.commit()
        conn.close()
        print("Severities updated!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    fix_sev()
