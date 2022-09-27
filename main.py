from blake3 import blake3
from hashlib import sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b, md5
from zlib import crc32
import os
from os import access, R_OK
import sys
from tkinter import *
from tkinter.messagebox import showinfo, showerror
from tkinter.filedialog import askopenfilename
import pyperclip
import threading


def resource_path(relative_path):
	""" Get absolute path to resource, works for dev and for PyInstaller """
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS
	except AttributeError:
		base_path = os.path.abspath(".")
	return os.path.join(base_path, relative_path)

def gen_blake2b(file, hex_hash=True):
	hasher = blake2b()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_blake2s(file, hex_hash=True):
	hasher = blake2s()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_blake3(file, hex_hash=True):
	hasher = blake3(max_threads=blake3.AUTO)
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_crc32(file, hex_hash=True):
	current_hash = 0
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			current_hash = crc32(chunk, current_hash)
	if hex_hash:
		return hex(current_hash)[2:]
	else:
		return bin(current_hash)

def gen_md5(file, hex_hash=True):
	hasher = md5()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha1(file, hex_hash=True):
	hasher = sha1()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha224(file, hex_hash=True):
	hasher = sha224()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha256(file, hex_hash=True):
	hasher = sha256()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha384(file, hex_hash=True):
	hasher = sha384()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha512(file, hex_hash=True):
	hasher = sha512()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha3_224(file, hex_hash=True):
	hasher = sha3_224()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha3_256(file, hex_hash=True):
	hasher = sha3_256()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha3_384(file, hex_hash=True):
	hasher = sha3_384()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def gen_sha3_512(file, hex_hash=True):
	hasher = sha3_512()
	with open(file, "rb") as file:
		while chunk := file.read(8192):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()

def hash_copy(event):
	global pi_generated, pi_value, root
	if pi_generated:
		pyperclip.copy(pi_value)
		showinfo(title="Copied!", message="Pi copied to clipboard!", parent=root)

def hash_select_click(event, widget, toplevel_win):
	global hash_selected, hash_selector
	hash_selected = widget["text"]
	hash_selector.config(text=hash_selected)
	toplevel_win.destroy()

def hash_select(event):
	global HASH_ALGOS, root

	hash_btns = []

	select_window = Toplevel(root, background="light blue")
	select_window.title("Select hash!")
	select_window.geometry(f"250x560+{root.winfo_screenwidth() // 2 - 125}+{root.winfo_screenheight() // 2 - 280}")
	select_window.resizable(False, False)
	select_window.iconbitmap(resource_path("data\\hash-icon.ico"))
	select_window.grab_set()
	select_window.focus()

	curr_y = 0
	for i in HASH_ALGOS:
		hash_btns.append(Label(select_window,
		                       text=i, font=("Helvetica", 15, "bold"),
		                       borderwidth=0, highlightthickness=0,
		                       background="light blue", activebackground="light blue",
		                       foreground="#ffffff", activeforeground="#ffffff"))
		hash_btns[-1].place(x=0, y=curr_y, width=250, height=40)
		hash_btns[-1].bind("<Enter>", lambda event=event, widget=hash_btns[-1]: widget.config(background="#B5E2F0", activebackground="#B5E2F0"))
		hash_btns[-1].bind("<Leave>", lambda event=event, widget=hash_btns[-1]: widget.config(background="light blue", activebackground="light blue"))
		hash_btns[-1].bind("<ButtonRelease-1>", lambda event=event, widget=hash_btns[-1]: hash_select_click(event, widget, select_window))
		curr_y += 40

	select_window.mainloop()
	select_window.grab_release()

def hover_algo(event, widget, typ):
	global disabled
	if not disabled:
		if typ:
			widget.config(background="#8AD9FF", activebackground="#8AD9FF")
		else:
			widget.config(background="#58c9ff", activebackground="#58c9ff")

def change_thickness(event, widget, typ):
	global disabled
	if not disabled:
		if typ:
			widget.config(highlightthickness=1)
		else:
			widget.config(highlightthickness=3)

def browse_click(event):
	global root, file_ent, disabled
	if not disabled:
		init_dir = os.path.dirname(file_ent.get())
		if not os.path.isdir(init_dir):
			init_dir = os.path.dirname(sys.executable)
		if not os.path.isdir(init_dir):
			init_dir = os.path.join(os.path.expanduser('~'), 'Desktop')
		selection = askopenfilename(initialdir=init_dir, parent=root)
		if os.path.isfile(selection) and access(selection, R_OK):
			file_ent.delete(0, END)
			file_ent.insert(0, selection.replace("/", "\\"))
			file_ent.xview_moveto(1)

def hash_click(event):


def main():
	global root, file_ent, disabled, HASH_ALGOS, hash_selected, hash_selector

	HASH_ALGOS = ["BLAKE2B", "BLAKE2S", "BLAKE3", "CRC32", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3 224", "SHA3 256", "SHA3 384", "SHA3 512"]

	disabled = False

	root = Tk()
	root.resizable(False, False)
	root.title("F-Hasher")
	root.geometry(f"750x500+{root.winfo_screenwidth() // 2 - 375}+{root.winfo_screenheight() // 2 - 250}")
	root.iconbitmap(resource_path("data\\hash-icon.ico"))
	root.config(background="#58c9ff")

	title = Label(root,
	              text="F-Hasher", font=("Gabriola", 50, "italic", "bold"),
	              foreground="white", activeforeground="white",
	              background="#58c9ff", activebackground="#58c9ff",
	              highlightthickness=0, borderwidth=0)
	title.place(x=0, y=0, width=750, height=100)

	hash_selected = HASH_ALGOS[2]
	hash_lbl = Label(root,
	                 text="Hash algorithm:", font=("Gabriola", 25, "bold"),
	                 borderwidth=0,
	                 background="#58c9ff", activebackground="#58c9ff",
	                 foreground="#ffffff", activeforeground="#ffffff")

	hash_lbl.place(x=100, y=110, width=185, height=40)
	hash_selector = Label(root,
	                      text=hash_selected, font=("Helvetica", 15, "bold"),
	                      borderwidth=0,
	                      background="#58c9ff", activebackground="#58c9ff",
	                      foreground="#ffffff", activeforeground="#ffffff")
	hash_selector.place(x=300, y=110, width=120, height=40)
	hash_selector.bind("<Enter>", lambda event: hover_algo(event, hash_selector, True))
	hash_selector.bind("<Leave>", lambda event: hover_algo(event, hash_selector, False))
	hash_selector.bind("<ButtonRelease-1>", lambda event: hash_select(event))

	file_lbl = Label(root,
	                 text="File:", font=("Gabriola", 25, "bold"),
	                 borderwidth=0,
	                 background="#58c9ff", activebackground="#58c9ff",
	                 foreground="#ffffff", activeforeground="#ffffff")
	file_lbl.place(x=0, y=160, width=100, height=30)
	file_ent = Entry(root, font=("Helvetica", 10),
	                 borderwidth=0, highlightthickness=1, highlightbackground="#ffffff", highlightcolor="#ffffff",
	                 disabledbackground="#263939", disabledforeground="#ffffff",
	                 background="#406060", foreground="#ffffff",
	                 justify=LEFT,
	                 insertbackground="#ffffff")
	file_ent.place(x=100, y=160, width=425, height=30)
	browse_btn = Label(root,
	                   text="Browse", font=("Helvetica", 11, "bold"),
	                   highlightthickness=1, highlightbackground="#ffffff", highlightcolor="#ffffff", borderwidth=0,
	                   background="#406060", activebackground="#406060",
	                   foreground="#ffffff", activeforeground="#ffffff")
	browse_btn.place(x=550, y=160, width=75, height=30)
	browse_btn.bind("<Enter>", lambda event: change_thickness(event, browse_btn, False))
	browse_btn.bind("<Leave>", lambda event: change_thickness(event, browse_btn, True))
	browse_btn.bind("<ButtonRelease-1>", browse_click)

	start_hashing = Label(root,
	                      text="Hash", font=("Helvetica", 11, "bold"),
	                      highlightthickness=1, highlightbackground="#ffffff", highlightcolor="#ffffff", borderwidth=0,
	                      background="#406060", activebackground="#406060",
	                      foreground="#ffffff", activeforeground="#ffffff")
	start_hashing.place(x=650, y=160, width=75, height=30)
	start_hashing.bind("<Enter>", lambda event: change_thickness(event, start_hashing, False))
	start_hashing.bind("<Leave>", lambda event: change_thickness(event, start_hashing, True))
	start_hashing.bind("<ButtonRelease-1>", browse_click)

	root.mainloop()

	print(gen_blake2b(r"main.py"))
	print(gen_blake2s(r"main.py"))
	print(gen_blake3(r"main.py"))
	print(gen_crc32(r"main.py"))
	print(gen_md5(r"main.py"))
	print(gen_sha1(r"main.py"))
	print(gen_sha224(r"main.py"))
	print(gen_sha256(r"main.py"))
	print(gen_sha384(r"main.py"))
	print(gen_sha512(r"main.py"))
	print(gen_sha3_224(r"main.py"))
	print(gen_sha3_256(r"main.py"))
	print(gen_sha3_384(r"main.py"))
	print(gen_sha3_512(r"main.py"))


if __name__ == "__main__":
	main()
