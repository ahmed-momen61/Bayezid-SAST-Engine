import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # الثغرة هنا: دمج المدخلات مباشرة في الاستعلام
    # المخترق يقدر يدخل: 1 OR 1=1
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    
    print("Executing query:", query)
    cursor.execute(query)
    return cursor.fetchall()

# تجربة تشغيل بدالة مريبة
uid = "1' OR '1'='1"
get_user_data(uid)