import tkinter as tk
from tkinter import filedialog, messagebox, Text
from PIL import Image, ImageTk
import random
import base64
import hashlib
from cryptography.fernet import Fernet

# ================= CYBERSECURITY TERMINAL THEME COLORS =================
BG_COLOR = "#070b14"        
PANEL_COLOR = "#111922"     
LABEL_COLOR = "#18ff28"   
ACCENT_COLOR = "#0da7ff"   
BUTTON_BG = "#191e2a"       
BUTTON_FG = "#18ff28"     
BUTTON_ACTIVE_BG = "#0da7ff"
ERROR_BTN_BG = "#ff073a"    
ENTRY_BG = "#161b22"        
ENTRY_FG = "#e8ffea"       

FONT_MAIN = ("Consolas", 13, "bold")
FONT_HEADER = ("Consolas", 18, "bold")
FONT_TERMINAL = ("Consolas", 11)

# ================= TEXT ENCRYPTION =================
def generate_key_from_password(password):
    # Generates a key for Fernet using SHA256 hash of the password
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_text():
    plain_text = text_input.get("1.0", tk.END).strip()
    password = text_pass.get().strip()
    if not plain_text or not password:
        messagebox.showerror("Error", "Please enter text and password")
        return
    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        encrypted_text = fernet.encrypt(plain_text.encode())
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, encrypted_text.decode())
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_text():
    encrypted_text = text_input.get("1.0", tk.END).strip()
    password = text_pass.get().strip()
    if not encrypted_text or not password:
        messagebox.showerror("Error", "Please enter encrypted text and password")
        return
    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        decrypted_text = fernet.decrypt(encrypted_text.encode())
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, decrypted_text.decode())
    except Exception as e:
        messagebox.showerror("Decryption Failed", "Invalid password or corrupted data")

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
        messagebox.showwarning("Warning", "No encrypted text to copy.")

# ================= IMAGE ENCRYPTION =================

# Keep references for image previews
uploaded_img = None
decrypted_img = None

def show_uploaded_image(img_path):
    global uploaded_img
    img = Image.open(img_path)
    img.thumbnail((250, 250))
    uploaded_img = ImageTk.PhotoImage(img)
    uploaded_label.config(image=uploaded_img)
    uploaded_label.image = uploaded_img  # Keep reference

def show_decrypted_image(img_path):
    global decrypted_img
    img = Image.open(img_path)
    img.thumbnail((250, 250))
    decrypted_img = ImageTk.PhotoImage(img)
    decrypted_label.config(image=decrypted_img)
    decrypted_label.image = decrypted_img  # Keep reference

def encrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return
    show_uploaded_image(file_path)
    try:
        key_seed = int(img_pass.get())
    except:
        messagebox.showerror("Error", "Please enter a valid numeric key")
        return
    try:
        img = Image.open(file_path)
        pixels = list(img.getdata())
        random.seed(key_seed)
        random.shuffle(pixels)
        img.putdata(pixels)
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if save_path:
            img.save(save_path)
            messagebox.showinfo("Success", f"Encrypted image saved at:\n{save_path}")
            show_uploaded_image(save_path)
            decrypted_label.config(image='')  # Clear decrypted preview
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt image: {str(e)}")

def decrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[("PNG Files", "*.png")])
    if not file_path:
        return
    show_uploaded_image(file_path)  # Show encrypted image preview
    try:
        key_seed = int(img_pass.get())
    except:
        messagebox.showerror("Error", "Please enter a valid numeric key")
        return
    try:
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
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if save_path:
            img.save(save_path)
            messagebox.showinfo("Success", f"Decrypted image saved at:\n{save_path}")
            show_decrypted_image(save_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt image: {str(e)}")

def clear_image_fields():
    img_pass.delete(0, tk.END)
    uploaded_label.config(image='')
    decrypted_label.config(image='')

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
root.title("Cybersecurity Encryption Toolkit")
root.geometry("800x620")
root.configure(bg=BG_COLOR)

# ---------- HOME SCREEN ----------
home_frame = tk.Frame(root, bg=PANEL_COLOR)
tk.Label(home_frame, text="🔐 DataShield Encryption Toolkit", fg=ACCENT_COLOR, bg=PANEL_COLOR, font=FONT_HEADER).pack(pady=35)
tk.Label(home_frame, text="Select an option to begin", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_MAIN).pack(pady=10)
tk.Button(home_frame, text="Text Encryption", bg=BUTTON_BG, fg=BUTTON_FG, activebackground=BUTTON_ACTIVE_BG,
          font=FONT_TERMINAL, width=20, height=2, bd=0, cursor="hand2", command=show_text_ui).pack(pady=15)
tk.Button(home_frame, text="Image Encryption", bg=BUTTON_BG, fg=BUTTON_FG, activebackground=BUTTON_ACTIVE_BG,
          font=FONT_TERMINAL, width=20, height=2, bd=0, cursor="hand2", command=show_image_ui).pack(pady=4)
home_frame.pack(fill="both", expand=True)

# ---------- TEXT ENCRYPTION SCREEN ----------
text_frame = tk.Frame(root, bg=PANEL_COLOR)
tk.Label(text_frame, text="Text Encryption", fg=ACCENT_COLOR, bg=PANEL_COLOR, font=FONT_MAIN).pack(pady=(0,8))
tk.Label(text_frame, text="Enter Plain/Cipher Text:", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_TERMINAL).pack()
text_input = Text(text_frame, height=5, font=FONT_TERMINAL, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG, bd=0, relief="sunken")
text_input.pack(fill="x", padx=10, pady=(0,6))
tk.Label(text_frame, text="Password:", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_TERMINAL).pack()
text_pass = tk.Entry(text_frame, show="*", font=FONT_TERMINAL, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG)
text_pass.pack(fill="x", padx=10, pady=(0,10))

btn_f = tk.Frame(text_frame, bg=PANEL_COLOR)
tk.Button(btn_f, text="Encrypt", bg=BUTTON_BG, fg=BUTTON_FG, activebackground=BUTTON_ACTIVE_BG, font=FONT_TERMINAL, width=10, command=encrypt_text).pack(side="left", padx=6)
tk.Button(btn_f, text="Decrypt", bg=BUTTON_BG, fg=BUTTON_FG, activebackground=BUTTON_ACTIVE_BG, font=FONT_TERMINAL, width=10, command=decrypt_text).pack(side="left", padx=6)
tk.Button(btn_f, text="Clear", bg=ERROR_BTN_BG, fg=BUTTON_FG, font=FONT_TERMINAL, width=8, command=clear_text_fields).pack(side="left", padx=6)
tk.Button(btn_f, text="Copy", bg=ACCENT_COLOR, fg=BG_COLOR, font=FONT_TERMINAL, width=8, command=copy_encrypted_text).pack(side="left", padx=6)
tk.Button(btn_f, text="Back", bg="#444c5c", fg=ACCENT_COLOR, font=FONT_TERMINAL, width=8, command=show_home).pack(side="right", padx=6)
btn_f.pack(fill="x", padx=10, pady=5)

tk.Label(text_frame, text="Output:", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_TERMINAL).pack(pady=(10, 0))
text_output = Text(text_frame, height=5, font=FONT_TERMINAL, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG, bd=0, relief="sunken")
text_output.pack(fill="x", padx=10)

# ---------- IMAGE ENCRYPTION SCREEN ----------
image_frame = tk.Frame(root, bg=PANEL_COLOR)
tk.Label(image_frame, text="Image Encryption", fg=ACCENT_COLOR, bg=PANEL_COLOR, font=FONT_MAIN).pack(pady=(0,8))
tk.Label(image_frame, text="Numeric Key:", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_TERMINAL).pack()
img_pass = tk.Entry(image_frame, font=FONT_TERMINAL, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG)
img_pass.pack(fill="x", padx=10, pady=(0,8))

btn_f2 = tk.Frame(image_frame, bg=PANEL_COLOR)
tk.Button(btn_f2, text="Encrypt", bg=BUTTON_BG, fg=BUTTON_FG, activebackground=BUTTON_ACTIVE_BG, font=FONT_TERMINAL, width=12, command=encrypt_image).pack(side="left", padx=6)
tk.Button(btn_f2, text="Decrypt", bg=BUTTON_BG, fg=BUTTON_FG, activebackground=BUTTON_ACTIVE_BG, font=FONT_TERMINAL, width=12, command=decrypt_image).pack(side="left", padx=6)
tk.Button(btn_f2, text="Clear", bg=ERROR_BTN_BG, fg=BUTTON_FG, font=FONT_TERMINAL, width=10, command=clear_image_fields).pack(side="left", padx=6)
tk.Button(btn_f2, text="Back", bg="#444c5c", fg=ACCENT_COLOR, font=FONT_TERMINAL, width=8, command=show_home).pack(side="right", padx=6)
btn_f2.pack(fill="x", padx=10, pady=10)

# Image preview labels
uploaded_label = tk.Label(image_frame, bg=PANEL_COLOR)
uploaded_label.pack(pady=(10, 0))
tk.Label(image_frame, text="Uploaded / Encrypted Image", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_TERMINAL).pack()

decrypted_label = tk.Label(image_frame, bg=PANEL_COLOR)
decrypted_label.pack(pady=(10, 10))
tk.Label(image_frame, text="Decrypted Image", fg=LABEL_COLOR, bg=PANEL_COLOR, font=FONT_TERMINAL).pack()

root.mainloop()
