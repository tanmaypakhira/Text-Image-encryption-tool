import tkinter as tk
from tkinter import filedialog, messagebox, Text
from PIL import Image
import random
import base64, hashlib
from cryptography.fernet import Fernet

# ================= CYBERSECURITY THEME COLORS =================
BG_COLOR = "#0f111a"        # Dark background
BTN_COLOR = "#39ff14"       # Neon green buttons
BTN_COLOR_ALT = "#00bfff"   # Electric blue buttons
LABEL_COLOR = "#d0d0d0"     # Light gray text
ERROR_BTN_COLOR = "#ff073a" # Neon red for error/clear buttons
ENTRY_BG = "#1b1f2a"        # Dark slate gray for text fields

LABEL_FONT = ("Segoe UI", 13, "bold")
BTN_FONT = ("Segoe UI", 12, "bold")
ENTRY_FONT = ("Segoe UI", 12)

# ================= TEXT ENCRYPTION =================
def generate_key_from_password(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_text():
    plain_text = text_input.get("1.0", tk.END).strip()
    password = text_pass.get().strip()
    if not plain_text or not password:
        messagebox.showerror("Error", "Enter text and password")
        return
    key = generate_key_from_password(password)
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(plain_text.encode())
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, encrypted_text.decode())

def decrypt_text():
    encrypted_text = text_input.get("1.0", tk.END).strip()
    password = text_pass.get().strip()
    if not encrypted_text or not password:
        messagebox.showerror("Error", "Enter encrypted text and password")
        return
    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        decrypted_text = fernet.decrypt(encrypted_text.encode())
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, decrypted_text.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Decryption Failed: {str(e)}")

def clear_text_fields():
    text_input.delete("1.0", tk.END)
    text_pass.delete(0, tk.END)
    text_output.delete("1.0", tk.END)

def copy_encrypted_text():
    encrypted_text = text_output.get("1.0", tk.END).strip()
    if encrypted_text:
        root.clipboard_clear()
        root.clipboard_append(encrypted_text)
        messagebox.showinfo("Copied", "Encrypted text copied to clipboard.")
    else:
        messagebox.showwarning("Warning", "Nothing to copy.")

# ================= IMAGE ENCRYPTION =================
def encrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return
    try:
        key_seed = int(img_pass.get())
    except:
        messagebox.showerror("Error", "Enter a numeric key")
        return
    img = Image.open(file_path)
    pixels = list(img.getdata())
    random.seed(key_seed)
    random.shuffle(pixels)
    img.putdata(pixels)
    save_path = filedialog.asksaveasfilename(defaultextension=".png")
    if save_path:
        img.save(save_path)
        messagebox.showinfo("Success", f"Encrypted image saved at {save_path}")

def decrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[("PNG Files", "*.png")])
    if not file_path:
        return
    try:
        key_seed = int(img_pass.get())
    except:
        messagebox.showerror("Error", "Enter a numeric key")
        return
    img = Image.open(file_path)
    pixels = list(img.getdata())
    random.seed(key_seed)
    indices = list(range(len(pixels)))
    shuffled_indices = indices.copy()
    random.shuffle(shuffled_indices)
    original_pixels = [None] * len(pixels)
    for i, shuf_i in enumerate(shuffled_indices):
        original_pixels[shuf_i] = pixels[i]
    img.putdata(original_pixels)
    save_path = filedialog.asksaveasfilename(defaultextension=".png")
    if save_path:
        img.save(save_path)
        messagebox.showinfo("Success", f"Decrypted image saved at {save_path}")

def clear_image_fields():
    img_pass.delete(0, tk.END)

# ================= SCREEN NAVIGATION =================
def show_text_ui():
    home_frame.pack_forget()
    image_frame.pack_forget()
    text_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_image_ui():
    home_frame.pack_forget()
    text_frame.pack_forget()
    image_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_home():
    text_frame.pack_forget()
    image_frame.pack_forget()
    home_frame.pack(fill="both", expand=True, padx=20, pady=20)

# ================= MAIN TKINTER SETUP =================
root = tk.Tk()
root.title("Text & Image Encryption Tool")
root.geometry("760x520")
root.configure(bg=BG_COLOR)

# ---------- HOME SCREEN ----------
home_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(home_frame, text="🔐 Welcome to Encryption Tool!", fg=LABEL_COLOR, bg=BG_COLOR, font=("Segoe UI", 20, "bold")).pack(pady=35)
tk.Label(home_frame, text="What would you like to do?", fg=LABEL_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(pady=10)
tk.Button(home_frame, text="Text Encryption", bg=BTN_COLOR, fg=BG_COLOR, font=BTN_FONT, height=2, width=16, bd=0, command=show_text_ui).pack(pady=15)
tk.Button(home_frame, text="Image Encryption", bg=BTN_COLOR_ALT, fg=BG_COLOR, font=BTN_FONT, height=2, width=16, bd=0, command=show_image_ui).pack(pady=2)
home_frame.pack(fill="both", expand=True, padx=20, pady=20)

# ---------- TEXT ENCRYPTION SCREEN ----------
text_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(text_frame, text="TEXT ENCRYPTION", fg=BTN_COLOR, bg=BG_COLOR, font=("Segoe UI", 17, "bold")).pack(pady=(0,8))
tk.Label(text_frame, text="Enter Text / Encrypted Text:", fg=LABEL_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack()
text_input = Text(text_frame, height=5, font=ENTRY_FONT, bg=ENTRY_BG, fg=LABEL_COLOR)
text_input.pack(fill="x", pady=(0,6))
tk.Label(text_frame, text="Password:", fg=LABEL_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack()
text_pass = tk.Entry(text_frame, show="*", font=ENTRY_FONT, bg=ENTRY_BG, fg=LABEL_COLOR)
text_pass.pack(fill="x", pady=(0,10))

btn_f = tk.Frame(text_frame, bg=BG_COLOR)
tk.Button(btn_f, text="Encrypt", bg=BTN_COLOR, fg=BG_COLOR, font=BTN_FONT, command=encrypt_text, width=10).pack(side="left", padx=6)
tk.Button(btn_f, text="Decrypt", bg=BTN_COLOR_ALT, fg=BG_COLOR, font=BTN_FONT, command=decrypt_text, width=10).pack(side="left", padx=6)
tk.Button(btn_f, text="Clear", bg=ERROR_BTN_COLOR, fg=BG_COLOR, font=BTN_FONT, command=clear_text_fields, width=8).pack(side="left", padx=6)
tk.Button(btn_f, text="Copy", bg="#4cafef", fg=BG_COLOR, font=BTN_FONT, command=copy_encrypted_text, width=8).pack(side="left", padx=6)
tk.Button(btn_f, text="Back", bg="#9991E1", fg=BG_COLOR, font=BTN_FONT, command=show_home, width=8).pack(side="right", padx=6)
btn_f.pack(fill="x", pady=5)

tk.Label(text_frame, text="Output:", fg=LABEL_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(pady=(10, 0))
text_output = Text(text_frame, height=5, font=ENTRY_FONT, bg=ENTRY_BG, fg=LABEL_COLOR)
text_output.pack(fill="x")

# ---------- IMAGE ENCRYPTION SCREEN ----------
image_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(image_frame, text="IMAGE ENCRYPTION", fg=BTN_COLOR_ALT, bg=BG_COLOR, font=("Segoe UI", 17, "bold")).pack(pady=(0,8))
tk.Label(image_frame, text="Numeric Key:", fg=LABEL_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack()
img_pass = tk.Entry(image_frame, font=ENTRY_FONT, bg=ENTRY_BG, fg=LABEL_COLOR)
img_pass.pack(fill="x", pady=(0,8))

btn_f2 = tk.Frame(image_frame, bg=BG_COLOR)
tk.Button(btn_f2, text="Encrypt", bg=BTN_COLOR, fg=BG_COLOR, font=BTN_FONT, command=encrypt_image, width=12).pack(side="left", padx=6)
tk.Button(btn_f2, text="Decrypt", bg=BTN_COLOR_ALT, fg=BG_COLOR, font=BTN_FONT, command=decrypt_image, width=12).pack(side="left", padx=6)
tk.Button(btn_f2, text="Clear", bg=ERROR_BTN_COLOR, fg=BG_COLOR, font=BTN_FONT, command=clear_image_fields, width=10).pack(side="left", padx=6)
tk.Button(btn_f2, text="Back", bg="#9991E1", fg=BG_COLOR, font=BTN_FONT, command=show_home, width=8).pack(side="right", padx=6)
btn_f2.pack(fill="x", pady=10)

root.mainloop()
