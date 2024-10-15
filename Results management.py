import psycopg2

def connect_to_db():
    try:
        connection = psycopg2.connect(
            host="localhost",        
            database="database_db",    
            user="user_db",          
            password="password"      
        )
        return connection
    except Exception as e:
        print(f"Error: {e}")
        return None

def insert_student_result(student_id, subject_code, marks, grade):
    connection = connect_to_db()
    if connection is None:
        return "Database connection failed"
    
    try:
        cursor = connection.cursor()

        if not isinstance(student_id, int) or student_id <= 0:
            raise ValueError("Invalid student ID")
        if not isinstance(subject_code, str) or len(subject_code) != 6:
            raise ValueError("Invalid subject code")
        if not (0 <= marks <= 100):
            raise ValueError("Marks should be between 0 and 100")
        if grade not in ['A', 'B', 'C', 'D', 'E', 'F']:
            raise ValueError("Invalid grade")

        insert_query =()
        """
        INSERT INTO student_results (student_id, subject_code, marks, grade)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (student_id, subject_code, marks, grade))
        connection.commit()
        return "Result inserted successfully"
    
    except Exception as e:
        return f"Error: {e}"
    
    finally:
        cursor.close()
        connection.close()

def update_student_result(student_id, subject_code, new_marks, new_grade):
    connection = connect_to_db()
    if connection is None:
        return "Database connection failed"
    
    try:
        cursor = connection.cursor()

        if not isinstance(student_id, int) or student_id <= 0:
            raise ValueError("Invalid student ID")
        if not isinstance(subject_code, str) or len(subject_code) != 6:
            raise ValueError("Invalid subject code")
        if not (0 <= new_marks <= 100):
            raise ValueError("Marks should be between 0 and 100")
        if new_grade not in ['A', 'B', 'C', 'D', 'E', 'F']:
            raise ValueError("Invalid grade")

        update_query =()
        """
        UPDATE student_results
        SET marks = %s, grade = %s
        WHERE student_id = %s AND subject_code = %s
        """
        cursor.execute(update_query, (new_marks, new_grade, student_id, subject_code))
        connection.commit()
        
        if cursor.rowcount == 0:
            return "No matching record found to update"
        
        return "Result updated successfully"
    
    except Exception as e:
        return f"Error: {e}"
    
    finally:
        cursor.close()
        connection.close()

def delete_student_result(student_id, subject_code):
    connection = connect_to_db()
    if connection is None:
        return "Database connection failed"
    
    try:
        cursor = connection.cursor()

        if not isinstance(student_id, int) or student_id <= 0:
            raise ValueError("Invalid student ID")
        if not isinstance(subject_code, str) or len(subject_code) != 6:
            raise ValueError("Invalid subject code")

        delete_query =() 
        """
        DELETE FROM student_results
        WHERE student_id = %s AND subject_code = %s
        """
        cursor.execute(delete_query, (student_id, subject_code))
        connection.commit()

        if cursor.rowcount == 0:
            return "No matching record found to delete"
        
        return "Result deleted successfully"
    
    except Exception as e:
        return f"Error: {e}"
    
    finally:
        cursor.close()
        connection.close()

