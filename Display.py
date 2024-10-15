import tkinter as tk
from tkinter import messagebox

def submit_record():
    messagebox.showinfo("Submission", "Record Submitted!")

def delete_record():
    messagebox.showinfo("Deletion", "Record Deleted!")

def display_math_results():
    messagebox.showinfo("Results", "Displaying Math Results")

def display_English_results():
    messagebox.showinfo("Results", "Displaying English Results")

def display_chemistry_results():
    messagebox.showinfo("Results", "Displaying Chemistry Results")

def display_biology_results():
    messagebox.showinfo("Results", "Displaying biology Results")


root = tk.Tk()
root.title("Exam Records")
root.geometry("700x500")
root.config(bg="light green")

title_label = tk.Label(root, text="Exam Records", font=("impact", 24), fg="black", bg="white")
title_label.grid(row=0, column=0, columnspan=3, pady=10)

tk.Label(root, text="Name", bg="light green").grid(row=1, column=0, padx=10, pady=5, sticky="e")
name_entry = tk.Entry(root, width=30)
name_entry.grid(row=1, column=1, padx=10)

tk.Label(root, text="Gender", bg="light green").grid(row=2, column=0, padx=10, pady=5, sticky="e")
gender_var = tk.StringVar()
male_rb = tk.Radiobutton(root, text="Male", variable=gender_var, value="Male", bg="white", fg="red")
male_rb.grid(row=2, column=1, sticky="w")
female_rb = tk.Radiobutton(root, text="Female", variable=gender_var, value="Female", bg="white", fg="brown")
female_rb.grid(row=2, column=1, sticky="e")

tk.Label(root, text="Seat Number", bg="light green").grid(row=3, column=0, padx=10, pady=5, sticky="e")
roll_entry = tk.Entry(root, width=30)
roll_entry.grid(row=3, column=1, padx=10)

tk.Label(root, text="Script Number", bg="light green").grid(row=4, column=0, padx=10, pady=5, sticky="e")
roll_entry = tk.Entry(root, width=30)
roll_entry.grid(row=4, column=1, padx=10)

tk.Label(root, text="Addmision_Number", bg="light green").grid(row=5, column=0, padx=10, pady=5, sticky="e")
roll_entry = tk.Entry(root, width=30)
roll_entry.grid(row=5, column=1, padx=10)

tk.Label(root, text="Mathematics", bg="light green").grid(row=6, column=0, padx=10, pady=5, sticky="e")
math_entry = tk.Entry(root, width=30)
math_entry.grid(row=6, column=1, padx=10)

tk.Label(root, text="English", bg="light green").grid(row=7, column=0, padx=10, pady=5, sticky="e")
physics_entry = tk.Entry(root, width=30)
physics_entry.grid(row=7, column=1, padx=10)

tk.Label(root, text="Chemistry", bg="light green").grid(row=8, column=0, padx=10, pady=5, sticky="e")
chemistry_entry = tk.Entry(root, width=30)
chemistry_entry.grid(row=8, column=1, padx=10)
tk.Label(root, text="Biology", bg="light green").grid(row=9, column=0, padx=10, pady=5, sticky="e")
chemistry_entry = tk.Entry(root, width=30)
chemistry_entry.grid(row=9, column=1, padx=10)


submit_btn = tk.Button(root, text="Submit", command=submit_record, bg="grey", fg="light green", width=30)
submit_btn.grid(row=10, column=1, pady=10)

delete_btn = tk.Button(root, text="Delete A Record", command=delete_record, bg="grey", fg="light green", width=20)
delete_btn.grid(row=11, column=1, pady=5)

display_math_btn = tk.Button(root, text="Display Maths Results", command=display_math_results, bg="grey", fg="light green", width=20)
display_math_btn.grid(row=2, column=3, padx=10, pady=5)

display_physics_btn = tk.Button(root, text="Display English Results", command=display_English_results, bg="grey", fg="light green", width=20)
display_physics_btn.grid(row=3, column=3, padx=10, pady=5)

display_chemistry_btn = tk.Button(root, text="Display Chemistry Results", command=display_chemistry_results, bg="grey", fg="light green", width=20)
display_chemistry_btn.grid(row=4, column=3, padx=10, pady=5)

root.mainloop()
