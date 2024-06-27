import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import random

# Dummy user credentials (for demonstration purposes)
valid_users = {
    "user1": "password1",
    "user2": "password2"
}

# Caesar Cipher functions
def caesar_cipher_encrypt(plaintext, key, direction):
    ciphertext = ""
    key = key % 26
    if direction == "Left":
        key = -key
    for char in plaintext:
        if char.isalpha():
            shift = ord('A') if char.isupper() else ord('a')
            ciphertext += chr((ord(char) - shift + key) % 26 + shift)
        else:
            ciphertext += char
    return ciphertext

def caesar_cipher_decrypt(ciphertext, key, direction):
    plaintext = ""
    key = key % 26
    if direction == "Left":
        key = -key
    for char in ciphertext:
        if char.isalpha():
            shift = ord('A') if char.isupper() else ord('a')
            plaintext += chr((ord(char) - shift - key) % 26 + shift)
        else:
            plaintext += char
    return plaintext

# Function to authenticate user
def authenticate_user(username, password):
    if username in valid_users and valid_users[username] == password:
        return True
    else:
        return False

# Function to handle login
def handle_login():
    username = entry_username.get()
    password = entry_password.get()
    if authenticate_user(username, password):
        login_window.destroy()
        main_tool()
    else:
        messagebox.showerror("Error", "Invalid username or password.")

# Function to handle encryption
def encrypt_text():
    text = entry_text.get("1.0", tk.END).strip()
    try:
        key = int(entry_key.get())
    except ValueError:
        messagebox.showerror("Error", "Key must be an integer.")
        return
    direction = direction_var.get()
    result = caesar_cipher_encrypt(text, key, direction)
    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, result)

# Function to handle decryption
def decrypt_text():
    text = entry_text.get("1.0", tk.END).strip()
    try:
        key = int(entry_key.get())
    except ValueError:
        messagebox.showerror("Error", "Key must be an integer.")
        return
    direction = direction_var.get()
    result = caesar_cipher_decrypt(text, key, direction)
    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, result)

# Function to save text to a file
def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(entry_result.get("1.0", tk.END).strip())

# Function to load text from a file
def load_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            entry_text.delete("1.0", tk.END)
            entry_text.insert(tk.END, file.read().strip())

# Main Caesar Cipher tool function
def main_tool():
    root = tk.Tk()
    root.title("Caesar Cipher Tool")

    global entry_text, entry_key, entry_result, direction_var

    direction_var = tk.StringVar(value="Right")

    # Labels and entry fields
    direction_label = ttk.Label(root, text="Shift Direction:")
    direction_label.pack()
    direction_menu = ttk.OptionMenu(root, direction_var, "Right", "Right", "Left")
    direction_menu.pack()

    text_label = ttk.Label(root, text="Enter Text:")
    text_label.pack()
    entry_text = tk.Text(root, height=10, width=50)
    entry_text.pack()

    key_label = ttk.Label(root, text="Enter Key:")
    key_label.pack()
    entry_key = ttk.Entry(root)
    entry_key.pack()

    result_label = ttk.Label(root, text="Result:")
    result_label.pack()
    entry_result = tk.Text(root, height=10, width=50)
    entry_result.pack()

    # Buttons
    encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_text)
    encrypt_button.pack(pady=5)
    decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_text)
    decrypt_button.pack(pady=5)

    # Import and export buttons
    save_button = ttk.Button(root, text="Save to File", command=save_to_file)
    save_button.pack(pady=5)
    load_button = ttk.Button(root, text="Load from File", command=load_from_file)
    load_button.pack(pady=5)

    root.mainloop()

# Login window
login_window = tk.Tk()
login_window.title("Login")

login_frame = ttk.Frame(login_window, padding="10")
login_frame.pack(fill="both", expand=True)

username_label = ttk.Label(login_frame, text="Username:")
username_label.grid(row=0, column=0, sticky="W", pady=5)
entry_username = ttk.Entry(login_frame)
entry_username.grid(row=0, column=1, pady=5)

password_label = ttk.Label(login_frame, text="Password:")
password_label.grid(row=1, column=0, sticky="W", pady=5)
entry_password = ttk.Entry(login_frame, show="*")
entry_password.grid(row=1, column=1, pady=5)

login_button = ttk.Button(login_frame, text="Login", command=handle_login)
login_button.grid(row=2, column=0, columnspan=2, pady=10)

login_window.mainloop()
