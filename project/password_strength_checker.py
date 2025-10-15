import tkinter as tk
from tkinter import messagebox, font
import re
import bcrypt
import math

# Load common passwords from file
def load_common_passwords(file_path="common_passwords.txt"):
    try:
        with open(file_path, 'r') as file:
            return {line.strip().lower() for line in file}
    except FileNotFoundError:
        print("Debug: common_passwords.txt not found, proceeding without common password check")
        return set()

# Calculate password entropy
def calculate_entropy(password):
    char_set = 0
    if bool(re.search(r'[a-z]', password)): char_set += 26
    if bool(re.search(r'[A-Z]', password)): char_set += 26
    if bool(re.search(r'\d', password)): char_set += 10
    if bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)): char_set += 32
    return round(math.log2(char_set ** len(password)), 2) if char_set > 0 else 0

# Calculate strength score
def calculate_password_score(password, common_passwords):
    score = 0
    if password.lower() not in common_passwords:
        score += 15
    score += max(0, (len(password) - 8) * 5)  # Length bonus
    if bool(re.search(r'[A-Z]', password)):
        score += 10
    if bool(re.search(r'[a-z]', password)):
        score += 10
    if bool(re.search(r'\d', password)):
        score += 10
    if bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        score += 15
    return min(score, 100)

# Save result to file
def save_result(password, result, hashed, entropy):
    try:
        with open("password_results.txt", "a") as f:
            f.write(f"Password: {password}\nResult: {result}\nHash: {hashed}\nEntropy: {entropy} bits\n\n")
        messagebox.showinfo("Success", "Results saved to password_results.txt")
    except Exception as e:
        print(f"Debug: Error saving result: {str(e)}")
        messagebox.showerror("Error", f"Failed to save results: {str(e)}")

# Check password strength (for button click)
def check_password_strength():
    password = entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    common_passwords = load_common_passwords()
    score = calculate_password_score(password, common_passwords)
    entropy = calculate_entropy(password)
    if password.lower() in common_passwords:
        result = f"Weak: Password is too common!\nScore: {score}/100\nEntropy: {entropy} bits"
    elif score < 50:
        result = f"Weak: Improve complexity.\nScore: {score}/100\nEntropy: {entropy} bits"
    elif score < 80:
        result = f"Moderate: Good, but can be stronger.\nScore: {score}/100\nEntropy: {entropy} bits"
    else:
        result = f"Strong: Great password!\nScore: {score}/100\nEntropy: {entropy} bits"
    label_result.config(text=result, fg="red" if score < 50 else "orange" if score < 80 else "green")
    # Hash the password
    try:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        label_hash.config(text=f"Hashed (bcrypt): {hashed}")
        save_result(password, result, hashed, entropy)
    except Exception as e:
        print(f"Debug: Error hashing password: {str(e)}")
        messagebox.showerror("Error", f"Failed to hash password: {str(e)}")

# Real-time feedback (runs on key release, no popups)
def update_feedback(event):
    password = entry.get()
    if password:
        common_passwords = load_common_passwords()
        score = calculate_password_score(password, common_passwords)
        entropy = calculate_entropy(password)
        if password.lower() in common_passwords:
            result = f"Weak: Password is too common!\nScore: {score}/100\nEntropy: {entropy} bits"
        elif score < 50:
            result = f"Weak: Improve complexity.\nScore: {score}/100\nEntropy: {entropy} bits"
        elif score < 80:
            result = f"Moderate: Good, but can be stronger.\nScore: {score}/100\nEntropy: {entropy} bits"
        else:
            result = f"Strong: Great password!\nScore: {score}/100\nEntropy: {entropy} bits"
        label_result.config(text=result, fg="red" if score < 50 else "orange" if score < 80 else "green")
    else:
        label_result.config(text="Result: Enter a password to check", fg="black")

# Create GUI
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("500x450")
root.configure(bg="#f0f0f0")
root.resizable(False, False)

# Define fonts and styles
title_font = font.Font(family="Helvetica", size=16, weight="bold")
label_font = font.Font(family="Helvetica", size=12)
button_font = font.Font(family="Helvetica", size=10, weight="bold")

# Title
tk.Label(root, text="Password Strength Checker", font=title_font, bg="#f0f0f0", fg="#333").pack(pady=20)

# Frame for input
frame_input = tk.Frame(root, bg="#f0f0f0")
frame_input.pack(pady=10)
tk.Label(frame_input, text="Enter Password:", font=label_font, bg="#f0f0f0").pack(side="left", padx=10)
entry = tk.Entry(frame_input, show="*", width=30, font=label_font, relief="solid", borderwidth=1)
entry.pack(side="left", padx=10)

# Buttons
frame_buttons = tk.Frame(root, bg="#f0f0f0")
frame_buttons.pack(pady=10)
tk.Button(frame_buttons, text="Check Strength", command=check_password_strength, font=button_font, bg="#4CAF50", fg="white", relief="flat", padx=10, pady=5).pack(side="left", padx=5)

# Result label
label_result = tk.Label(root, text="Result: Enter a password to check", font=label_font, bg="#f0f0f0", fg="black", wraplength=450)
label_result.pack(pady=20)

# Hash label
label_hash = tk.Label(root, text="Hashed: ", font=label_font, bg="#f0f0f0", fg="black", wraplength=450)
label_hash.pack(pady=10)

# Real-time feedback binding
entry.bind("<KeyRelease>", update_feedback)

root.mainloop()
