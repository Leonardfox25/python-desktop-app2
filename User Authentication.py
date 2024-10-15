#!/usr/bin/python3
import bcrypt
import tkinter as tk
from tkinter import *
from tkinter import messagebox as msg 
from Database import connect
def validate_numeric_input(char):
    return char.isdigit() or char == ""

def on_closing():
    if msg.askokcancel("Quit", "Do you want to quit?"):
        main_screen.destroy()
def signup():
    global register_screen
    global username
    global username_entry
    global password_entry
    global email_entry

    register_screen = Toplevel(main_screen)
    register_screen.geometry("600x500")
    register_screen.title("Create an account")

    username = StringVar()
    password = StringVar()
    validate_cmd = register_screen.register(validate_numeric_input)


    Label(register_screen, text="").pack()
    Label(register_screen, text="Please enter the following details", bg="red", font=("Calibri", 13)).pack()

    # Username
    Label(register_screen, text="Username * ").pack()
    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()

    # Password
    Label(register_screen, text="Password * ").pack()
    password_entry = Entry(register_screen, textvariable=password, show="*")
    password_entry.pack()

    # Space and Register button
    Label(register_screen, text="").pack()
    Button(register_screen, text="Register", bg="green", font=("Calibri", 13), width=13, height=1, command=register_user).pack()

def register_user():
    # Declare global variables to use them inside the function
    global username, password
    global username_entry, password_entry
    
    username_info = username.get()
    password_info = password.get()

    # Hashing the password
    hashed_password = bcrypt.hashpw(password_info.encode('utf-8'), bcrypt.gensalt())
    conn = None
    cur = None
    try:
        # Connecting to the database
        conn = connect()
        cur = conn.cursor()
        if conn is None:
            msg.showerror("Error", "Database connection failed.")
            return
        # Inserting user data into the database
        cur.execute(
            """
            INSERT INTO user_acct(username, password)
            VALUES(%s, %s)
            """, (username_info, hashed_password.decode('utf-8'))
        )

        # Committing the transaction
        conn.commit()
    except Exception as e:
        msg.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

        # Clearing the form after successful registration
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        # Displaying success message
        Label(register_screen, text="Registration successful", fg="green", font=("Calibri", 13)).pack()

def login():
    # from main import main_screen
    global login_screen
    global password_entry
    global password

    login_screen = Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("600x500")

    email = StringVar()
    password = StringVar()

    # Instruction Label
    Label(login_screen, text="Please enter the following details", bg="red", font=("Calibri", 13)).pack()

    # Email input
    Label(login_screen, text="Email * ").pack()
    email_entry = Entry(login_screen, textvariable=email)
    email_entry.pack()

    # Password input
    Label(login_screen, text="Password * ").pack()
    password_entry = Entry(login_screen, textvariable=password, show="*")
    password_entry.pack()

    # Login Button
    Button(login_screen, text="Login", bg="green", command=login_verify).pack()

def login_verify():
    password_info = password_entry.get()

    # Connecting to the database
    conn = connect()
    cur = conn.cursor()
    
    # Fetch hashed password from database
    cur.execute(
        """
        SELECT password FROM user_acct WHERE username = %s
        """, (username,)
    )
    result = cur.fetchone()

    conn.close()
    
    if result:
        stored_hashed_password = result[0].encode('utf-8')
        # Check if entered password matches the hashed password
        if bcrypt.checkpw(password_info.encode('utf-8'), stored_hashed_password):
            login_success()
        else:
            password_invalid()
    else:
        user_not_found()

def login_success():
    global login_success_screen
    login_success_screen = Toplevel(login_screen)
    login_success_screen.title("Success")
    login_success_screen.geometry("150x100")
    
    Label(login_success_screen, text="Login successfully", fg="green", font=("Calibri", 13)).pack()
    Button(login_success_screen, text="OK", command=login_success_screen.destroy).pack()

def user_not_found():
    global user_not_found_screen
    user_not_found_screen = Toplevel(login_screen)
    user_not_found_screen.title("Failed")
    user_not_found_screen.geometry("150x100")
    
    Label(user_not_found_screen, text="User not found", fg="red", font=("Calibri", 13)).pack()
    Button(user_not_found_screen, text="OK", command=delete_user_not_found).pack()

def delete_user_not_found():
    user_not_found_screen.destroy()

def password_invalid():
    global password_invalid_screen
    password_invalid_screen = Toplevel(login_screen)
    password_invalid_screen.title("Invalid Password")
    password_invalid_screen.geometry("150x100")
    
    Label(password_invalid_screen, text="Password is invalid", fg="red", font=("Calibri", 13)).pack()
    Button(password_invalid_screen, text="OK", command=delete_password_invalid).pack()

def delete_password_invalid():
    password_invalid_screen.destroy()

def main_action_screen():
    global main_screen
    main_screen = Tk()
    main_screen.geometry("600x400")  # Adjusted to fit most screen sizes
    main_screen.title("User Account Login/Register")
    main_screen.protocol("WM_DELETE_WINDOW", on_closing)

    Label(text="Select your choice", bg="green", width="300", height="2", font=("Calibri", 13)).pack()

    Button(text="Register", bg="red", width="30", height="2", font=("Arial Bold", 10), command=signup).pack()
    Button(text="Login", bg="green", width="30", height="2", font=("Arial Bold", 10), command=login).pack()

    main_screen.mainloop()

main_action_screen()
