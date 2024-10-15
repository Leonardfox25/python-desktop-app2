students_data = [
     {"name": "Joshua", "Math": 75, "English": 67, "chemistry": 68, "biology":63},
    {"name": "Samuel", "Math": 72, "English": 95, "chemistry": 71, "biology":90},
    {"name": "Heritage", "Math": 90, "English": 87, "chemistry": 83, "biology":89}
    
    
]

def calculate_average(student):
    scores = [score for subject, score in student.items() if subject != "name"]
    average = sum(scores) / len(scores)
    return average
def top_performers(students_data):
    students_with_avg = [(student['name'], calculate_average(student)) for student in students_data]
    students_with_avg.sort(key=lambda x: x[1], reverse=True)
    return students_with_avg
import tkinter as tk

def generate_report():
    report_text.delete(3.0, tk.END)  
    
    report = top_performers(students_data)
    
    for name, avg in report:
        report_text.insert(tk.END, f"Student: {name}, Average: {avg:.2f}\n")

root = tk.Tk()
root.title("Student Report Generator")

generate_button = tk.Button(root, text="Generate Report", command=generate_report)
generate_button.pack(pady=10)

report_text = tk.Text(root, height=10, width=50)
report_text.pack(pady=10)

students_data = [
     {"name": "Joshua", "Math": 75, "English": 67, "chemistry": 68, "biology":63},
    {"name": "Samuel", "Math": 72, "English": 95, "chemistry": 71, "biology":90},
    {"name": "Heritage", "Math": 90, "English": 87, "chemistry": 83, "biology":89}
]

root.mainloop()
