import os
import sys
from hashlib import sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b, md5
from os import access, R_OK
from threading import Thread
import tkinter as tk
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showinfo, showerror
from zlib import crc32

import psutil
import pyperclip
from blake3 import blake3


HASH_ALGORITHMS = [
	"BLAKE2B",
	"BLAKE2S",
	"BLAKE3",
	"CRC32",
	"MD5",
	"SHA1",
	"SHA224",
	"SHA256",
	"SHA384",
	"SHA512",
	"SHA3 224",
	"SHA3 256",
	"SHA3 384",
	"SHA3 512"
]

CHUNK_SIZE = 2 ** 13


def resource_path(relative_path):
	""" Get absolute path to resource, works for dev and for PyInstaller """
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS
	except AttributeError:
		base_path = os.path.abspath(".")
	return os.path.join(base_path, relative_path)


class CRC32Wrapper:
	def __init__(self):
		self.crc = 0

	def update(self, data):
		self.crc = crc32(data, self.crc)

	def hexdigest(self):
		return hex(self.crc)[2:]

	def digest(self):
		return bin(self.crc)


def calculate_hash(file, hash_method, hex_hash=True):
	hasher = None

	match hash_method:
		case "BLAKE2B":
			hasher = blake2b()
		case "BLAKE2S":
			hasher = blake2s()
		case "BLAKE3":
			hasher = blake3(max_threads=blake3.AUTO)
		case "CRC32":
			hasher = CRC32Wrapper()
		case "MD5":
			hasher = md5()
		case "SHA1":
			hasher = sha1()
		case "SHA224":
			hasher = sha224()
		case "SHA256":
			hasher = sha256()
		case "SHA384":
			hasher = sha384()
		case "SHA512":
			hasher = sha512()
		case "SHA3 224":
			hasher = sha3_224()
		case "SHA3 256":
			hasher = sha3_256()
		case "SHA3 384":
			hasher = sha3_384()
		case "SHA3 512":
			hasher = sha3_512()

	with open(file, "rb") as file:
		while chunk := file.read(CHUNK_SIZE):
			hasher.update(chunk)
	if hex_hash:
		return hasher.hexdigest()
	else:
		return hasher.digest()


class App():
	def __init__(self):
		self.root = tk.Tk()
		self.root.resizable(False, False)
		self.root.title("F-Hasher")
		self.root.geometry(f"750x250+{self.root.winfo_screenwidth() // 2 - 375}+{self.root.winfo_screenheight() // 2 - 125}")
		self.root.iconbitmap(resource_path("resources\\hash-icon.ico"))
		self.root.config(background="#58c9ff")

		self.title = tk.Label(self.root,
		                      text="F-Hasher", font=("Gabriola", 50, "italic", "bold"),
		                      foreground="white", activeforeground="white",
		                      background="#58c9ff", activebackground="#58c9ff",
		                      highlightthickness=0, borderwidth=0)
		self.title.place(x=0, y=0, width=750, height=100)

		self.hash_lbl = tk.Label(self.root,
		                         text="Hash algorithm:", font=("Gabriola", 25, "bold"),
		                         borderwidth=0,
		                         background="#58c9ff", activebackground="#58c9ff",
		                         foreground="#ffffff", activeforeground="#ffffff")
		self.hash_lbl.place(x=100, y=110, width=185, height=40)

		self.hash_selector = tk.Label(self.root,
		                              text=hash_selected, font=("Helvetica", 15, "bold"),
		                              borderwidth=0,
		                              background="#58c9ff", activebackground="#58c9ff",
		                              foreground="#ffffff", activeforeground="#ffffff")
		self.hash_selector.place(x=300, y=110, width=120, height=40)
		self.hash_selector.bind("<Enter>", lambda event: hover_algo(event, hash_selector, True))
		self.hash_selector.bind("<Leave>", lambda event: hover_algo(event, hash_selector, False))
		self.hash_selector.bind("<ButtonRelease-1>", lambda event: hash_select(event))

		self.file_lbl = tk.Label(self.root,
		                         text="File:", font=("Gabriola", 25, "bold"),
		                         borderwidth=0,
		                         background="#58c9ff", activebackground="#58c9ff",
		                         foreground="#ffffff", activeforeground="#ffffff")
		self.file_lbl.place(x=0, y=160, width=100, height=30)

		self.file_ent = tk.Entry(self.root, font=("Helvetica", 10),
		                         borderwidth=0, highlightthickness=1,
		                         highlightbackground="#ffffff", highlightcolor="#ffffff",
		                         disabledbackground="#263939", disabledforeground="#ffffff",
		                         background="#406060", foreground="#ffffff",
		                         justify=tk.LEFT, insertbackground="#ffffff")
		self.file_ent.place(x=100, y=160, width=425, height=30)

		self.browse_btn = tk.Label(self.root,
		                           text="Browse", font=("Helvetica", 11, "bold"),
		                           highlightthickness=1, highlightbackground="#ffffff",
		                           highlightcolor="#ffffff", borderwidth=0,
		                           background="#406060", activebackground="#406060",
		                           foreground="#ffffff", activeforeground="#ffffff")
		self.browse_btn.place(x=550, y=160, width=75, height=30)
		self.browse_btn.bind("<Enter>", lambda event: change_thickness(event, browse_btn, False))
		self.browse_btn.bind("<Leave>", lambda event: change_thickness(event, browse_btn, True))
		self.browse_btn.bind("<ButtonRelease-1>", browse_click)

		self.start_hashing = tk.Label(self.root,
		                              text="Hash", font=("Helvetica", 11, "bold"),
		                              highlightthickness=1, highlightbackground="#ffffff",
		                              highlightcolor="#ffffff", borderwidth=0,
		                              background="#406060", activebackground="#406060",
		                              foreground="#ffffff", activeforeground="#ffffff")
		self.start_hashing.place(x=650, y=160, width=75, height=30)
		self.start_hashing.bind("<Enter>", lambda event: change_thickness(event, start_hashing, False))
		self.start_hashing.bind("<Leave>", lambda event: change_thickness(event, start_hashing, True))
		self.start_hashing.bind("<ButtonRelease-1>", hash_click)

		self.output_hash = tk.Label(self.root,
		                            text="", font=("Helvetica", 14, "bold"),
		                            borderwidth=0,
		                            background="#58c9ff", activebackground="#58c9ff",
		                            foreground="#ffffff", activeforeground="#ffffff")
		self.output_hash.place(x=0, y=190, width=750, height=60)
		self.output_hash.bind("<Enter>", lambda event: hover_hash(event, output_hash, True))
		self.output_hash.bind("<Leave>", lambda event: hover_hash(event, output_hash, False))
		self.output_hash.bind("<ButtonRelease-1>", lambda event: hash_copy(event))

		global root, file_ent, disabled, hash_selected, hash_selector, start_hashing, output_hash, browse_btn, hashed
		hashed = ""
		disabled = False

		hash_selected = HASH_ALGORITHMS[2]

		self.root.mainloop()


def hash_copy(event):
	global disabled, output_hash, hashed
	if not disabled and output_hash["text"] != "":
		pyperclip.copy(hashed)
		showinfo(title="Copied!", message="Hash value copied to clipboard!", parent=root)


def hash_select_click(event, widget, toplevel_win):
	global hash_selected, hash_selector, hashed, output_hash
	hash_selected = widget["text"]
	hash_selector.config(text=hash_selected)
	toplevel_win.destroy()
	hashed = ""
	output_hash.config(text="")


def hash_select(event):
	global root, disabled
	if not disabled:
		hash_btns = []

		select_window = tk.Toplevel(root, background="light blue")
		select_window.title("Select hash!")
		select_window.geometry(f"250x560+{root.winfo_screenwidth() // 2 - 125}+{root.winfo_screenheight() // 2 - 280}")
		select_window.resizable(False, False)
		select_window.iconbitmap(resource_path("resources\\hash-icon.ico"))
		select_window.grab_set()
		select_window.focus()

		curr_y = 0
		for i in HASH_ALGORITHMS:
			hash_btns.append(tk.Label(select_window,
			                          text=i, font=("Helvetica", 15, "bold"),
			                          borderwidth=0, highlightthickness=0,
			                          background="light blue", activebackground="light blue",
			                          foreground="#ffffff", activeforeground="#ffffff"))
			hash_btns[-1].place(x=0, y=curr_y, width=250, height=40)
			hash_btns[-1].bind("<Enter>", lambda event, widget=hash_btns[-1]: widget.config(background="#B5E2F0",
			                                                                                activebackground="#B5E2F0"))
			hash_btns[-1].bind("<Leave>", lambda event, widget=hash_btns[-1]: widget.config(background="light blue",
			                                                                                activebackground="light blue"))
			hash_btns[-1].bind("<ButtonRelease-1>",
			                   lambda event, widget=hash_btns[-1]: hash_select_click(event, widget, select_window))
			curr_y += 40

		select_window.wait_window()


def hover_algo(event, widget, typ):
	global disabled
	if not disabled:
		if typ:
			widget.config(background="#8AD9FF", activebackground="#8AD9FF")
		else:
			widget.config(background="#58c9ff", activebackground="#58c9ff")


def hover_hash(event, widget, typ):
	global disabled
	if not disabled and widget["text"] != "":
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
			file_ent.delete(0, tk.END)
			file_ent.insert(0, selection.replace("/", "\\"))
			file_ent.xview_moveto(1)


def hash_file(file, hash_method):
	global disabled, file_ent, start_hashing, output_hash, browse_btn, hashed

	hashed = calculate_hash(file, hash_method)

	disabled = False
	start_hashing.config(text="Hash", background="#406060", activebackground="#406060")
	browse_btn.config(background="#406060", activebackground="#406060")
	file_ent.config(state="normal")

	if len(hashed) > 64:
		output_hash.config(text=f"{hashed[:32]}...{hashed[-32:]}")
	else:
		output_hash.config(text=hashed)


def hash_click(event):
	global disabled, file_ent, root, start_hashing, hash_selected, browse_btn

	content = file_ent.get()

	if os.path.isfile(content) and access(content, R_OK):
		hash_thread = Thread(target=hash_file, args=(content, hash_selected))
		hash_thread.start()
		disabled = True
		start_hashing.config(highlightthickness=1, text="Hashing", background="#263939", activebackground="#263939")
		browse_btn.config(background="#263939", activebackground="#263939")
		file_ent.config(state="disabled")
	else:
		showerror(title="Invalid file!", message="The selected file can't be processed!", parent=root)


def main():
	App()

	# to prevent ongoing hashing from stopping the closing of the app
	psutil.Process(os.getpid()).kill()


if __name__ == "__main__":
	main()
