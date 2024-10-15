import tkinter as tk
from tkinter import ttk, messagebox

class StudentRecordsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Records Management")
        self.root.geometry("1500x800")

        self.student_data = []

        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=20)

        self.name_label = tk.Label(self.frame, text="Name:")
        self.name_label.grid(row=0, column=0, padx=10, pady=5)
        self.name_entry = tk.Entry(self.frame)
        self.name_entry.grid(row=0, column=1, padx=10, pady=5)

        self.age_label = tk.Label(self.frame, text="Age:")
        self.age_label.grid(row=1, column=0, padx=10, pady=5)
        self.age_entry = tk.Entry(self.frame)
        self.age_entry.grid(row=1, column=1, padx=10, pady=5)

        self.grade_label = tk.Label(self.frame, text="Grade:")
        self.grade_label.grid(row=2, column=0, padx=10, pady=5)
        self.grade_entry = tk.Entry(self.frame)
        self.grade_entry.grid(row=2, column=1, padx=10, pady=5)


        self.add_button = tk.Button(self.frame, text="Add", command=self.add_student)
        self.add_button.grid(row=5, column=0, padx=10, pady=10)

        self.update_button = tk.Button(self.frame, text="Update", command=self.update_student)
        self.update_button.grid(row=5, column=1, padx=10, pady=10)

        self.delete_button = tk.Button(self.frame, text="Delete", command=self.delete_student)
        self.delete_button.grid(row=5, column=2, padx=10, pady=10)

        self.tree = ttk.Treeview(self.root, columns=("Name", "Age", "Grade"), show="headings")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Age", text="Age")
        self.tree.heading("Grade", text="Grade")
        self.tree.pack(pady=20)

        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

    def add_student(self):
        name = self.name_entry.get()
        age = self.age_entry.get()
        grade = self.grade_entry.get()

        if name and age.isdigit() and grade:
            self.student_data.append((name, int(age), grade))
            self.refresh_treeview()
            self.clear_form()
        else:
            messagebox.showerror("Input Error", "Please enter valid data.")

    def update_student(self):
        selected_item = self.tree.selection()
        if selected_item:
            name = self.name_entry.get()
            age = self.age_entry.get()
            grade = self.grade_entry.get()

            if name and age.isdigit() and grade:
                selected_index = self.tree.index(selected_item[0])
                self.student_data[selected_index] = (name, int(age), grade)
                self.refresh_treeview()
                self.clear_form()
            else:
                messagebox.showerror("Input Error", "Please enter valid data.")
        else:
            messagebox.showerror("Selection Error", "Please select a student to update.")

    def delete_student(self):
        selected_item = self.tree.selection()
        if selected_item:
            selected_index = self.tree.index(selected_item[0])
            del self.student_data[selected_index]
            self.refresh_treeview()
            self.clear_form()
        else:
            messagebox.showerror("Selection Error", "Please select a student to delete.")

    def refresh_treeview(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for student in self.student_data:
            self.tree.insert("", "end", values=student)

    def clear_form(self):
        self.name_entry.delete(0, tk.END)
        self.age_entry.delete(0, tk.END)
        self.grade_entry.delete(0, tk.END)

    def on_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            selected_index = self.tree.index(selected_item[0])
            selected_student = self.student_data[selected_index]
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, selected_student[0])
            self.age_entry.delete(0, tk.END)
            self.age_entry.insert(0, selected_student[1])
            self.grade_entry.delete(0, tk.END)
            self.grade_entry.insert(0, selected_student[2])

if __name__ == "__main__":
    root = tk.Tk()
    app = StudentRecordsApp(root)
    root.mainloop()
