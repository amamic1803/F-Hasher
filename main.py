import os
import sys
from hashlib import sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b, md5
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

class App:
	def __init__(self):
		self.current_hash_algorithm = HASH_ALGORITHMS[2]
		self.current_calculated_hash = ""
		self.state = True  # True = gui enabled, not hashing, False = gui disabled, hashing
		self.gui_alive = True  # True = gui alive, False = gui destroyed, stops hashing thread

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
		                              text=self.current_hash_algorithm, font=("Helvetica", 15, "bold"), cursor="hand2",
		                              borderwidth=0,
		                              background="#58c9ff", activebackground="#58c9ff",
		                              foreground="#ffffff", activeforeground="#ffffff")
		self.hash_selector.place(x=300, y=110, width=120, height=40)
		self.hash_selector.bind("<Enter>", lambda event: self.algorithm_btn_hover(event, self.hash_selector, True))
		self.hash_selector.bind("<Leave>", lambda event: self.algorithm_btn_hover(event, self.hash_selector, False))
		self.hash_selector.bind("<ButtonRelease-1>", self.select_hash_algorithm)

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
		                           text="Browse", font=("Helvetica", 11, "bold"), cursor="hand2",
		                           highlightthickness=1, highlightbackground="#ffffff",
		                           highlightcolor="#ffffff", borderwidth=0,
		                           background="#406060", activebackground="#406060",
		                           foreground="#ffffff", activeforeground="#ffffff")
		self.browse_btn.place(x=550, y=160, width=75, height=30)
		self.browse_btn.bind("<Enter>", lambda event: self.change_thickness(event, self.browse_btn, True))
		self.browse_btn.bind("<Leave>", lambda event: self.change_thickness(event, self.browse_btn, False))
		self.browse_btn.bind("<ButtonRelease-1>", self.browse_files)

		self.start_hashing = tk.Label(self.root,
		                              text="Hash", font=("Helvetica", 11, "bold"), cursor="hand2",
		                              highlightthickness=1, highlightbackground="#ffffff",
		                              highlightcolor="#ffffff", borderwidth=0,
		                              background="#406060", activebackground="#406060",
		                              foreground="#ffffff", activeforeground="#ffffff")
		self.start_hashing.place(x=650, y=160, width=75, height=30)
		self.start_hashing.bind("<Enter>", lambda event: self.change_thickness(event, self.start_hashing, True))
		self.start_hashing.bind("<Leave>", lambda event: self.change_thickness(event, self.start_hashing, False))
		self.start_hashing.bind("<ButtonRelease-1>", self.hash_click)

		self.output_hash = tk.Label(self.root,
		                            text="", font=("Helvetica", 14, "bold"),
		                            borderwidth=0,
		                            background="#58c9ff", activebackground="#58c9ff",
		                            foreground="#ffffff", activeforeground="#ffffff")
		self.output_hash.place(x=0, y=190, width=750, height=60)
		self.output_hash.bind("<Enter>", lambda event: self.output_hash_hover(event, self.output_hash, True))
		self.output_hash.bind("<Leave>", lambda event: self.output_hash_hover(event, self.output_hash, False))
		self.output_hash.bind("<ButtonRelease-1>", self.copy_hash)

		self.root.mainloop()

	def change_thickness(self, event, widget, enter=True):
		if self.state:
			if enter:
				widget.config(highlightthickness=3)
			else:
				widget.config(highlightthickness=1)

	def algorithm_btn_hover(self, event, widget, enter=True):
		if self.state:
			if enter:
				widget.config(background="#8AD9FF", activebackground="#8AD9FF")
			else:
				widget.config(background="#58c9ff", activebackground="#58c9ff")

	def output_hash_hover(self, event, widget, enter=True):
		if self.state and self.current_calculated_hash != "":
			if enter:
				widget.config(background="#8AD9FF", activebackground="#8AD9FF")
			else:
				widget.config(background="#58c9ff", activebackground="#58c9ff")

	def select_hash_algorithm(self, event):
		if self.state:
			select_hash = SelectHash(self.root)
			select_hash = select_hash.result()
			if select_hash != "":
				self.current_hash_algorithm = select_hash
				self.hash_selector.config(text=self.current_hash_algorithm)
				self.current_calculated_hash = ""
				self.output_hash.config(text="", cursor="arrow")

	def browse_files(self, event):
		if self.state:
			initial_dir = os.path.dirname(self.file_ent.get())
			if not os.path.isdir(initial_dir):
				initial_dir = os.path.dirname(sys.executable)
			if not os.path.isdir(initial_dir):
				initial_dir = os.path.join(os.path.expanduser('~'), 'Desktop')
			selection = askopenfilename(initialdir=initial_dir, parent=self.root)
			if os.path.isfile(selection) and os.access(selection, os.R_OK):
				self.file_ent.delete(0, tk.END)
				self.file_ent.insert(0, selection.replace("/", "\\"))
				self.file_ent.xview_moveto(1)

	def copy_hash(self, event):
		if self.state and self.current_calculated_hash != "":
			pyperclip.copy(self.current_calculated_hash)
			showinfo(title="Copied!", message="Hash value copied to clipboard!", parent=self.root)

	def hash_click(self, event):
		file_path = self.file_ent.get()

		if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
			hash_thread = Thread(target=self.calculate_hash, args=(file_path, self.current_hash_algorithm))
			hash_thread.start()
			self.state = False
			self.start_hashing.config(highlightthickness=1, text="Hashing", background="#263939", activebackground="#263939", cursor="arrow")
			self.browse_btn.config(background="#263939", activebackground="#263939", cursor="arrow")
			self.file_ent.config(state="disabled")
			self.output_hash.config(text="", cursor="arrow")
			self.hash_selector.config(cursor="arrow")
		else:
			showerror(title="Invalid file!", message="The selected file can't be processed!", parent=self.root)

	def calculate_hash(self, file, hash_method, hex_hash=True):
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
			while (chunk := file.read(CHUNK_SIZE)) and self.gui_alive:
				hasher.update(chunk)

		self.update_hash(hasher.hexdigest() if hex_hash else hasher.digest())

	def update_hash(self, hash_value):
		self.state = True
		self.start_hashing.config(text="Hash", background="#406060", activebackground="#406060", cursor="hand2")
		self.browse_btn.config(background="#406060", activebackground="#406060", cursor="hand2")
		self.file_ent.config(state="normal")
		if hash_value != "":
			self.output_hash.config(cursor="hand2")
		self.hash_selector.config(cursor="hand2")
		self.current_calculated_hash = hash_value

		if len(hash_value) > 64:
			self.output_hash.config(text=f"{hash_value[:32]}...{hash_value[-32:]}")
		else:
			self.output_hash.config(text=hash_value)

class SelectHash:
	def __init__(self, root):
		self.result_str = ""
		self.window = tk.Toplevel(root, background="light blue")
		self.window.title("Select hash!")
		self.window.geometry(f"250x560+{root.winfo_screenwidth() // 2 - 125}+{root.winfo_screenheight() // 2 - 280}")
		self.window.resizable(False, False)
		self.window.iconbitmap(resource_path("resources\\hash-icon.ico"))
		self.window.grab_set()
		self.window.focus()

		self.hash_btns = []

		curr_y = 0
		for i in HASH_ALGORITHMS:
			self.hash_btns.append(tk.Label(self.window,
			                               text=i, font=("Helvetica", 15, "bold"), cursor="hand2",
			                               borderwidth=0, highlightthickness=0,
			                               background="light blue", activebackground="light blue",
			                               foreground="#ffffff", activeforeground="#ffffff"))
			self.hash_btns[-1].place(x=0, y=curr_y, width=250, height=40)
			self.hash_btns[-1].bind("<Enter>",
			                        lambda event, widget=self.hash_btns[-1]: widget.config(background="#B5E2F0", activebackground="#B5E2F0"))
			self.hash_btns[-1].bind("<Leave>",
			                        lambda event, widget=self.hash_btns[-1]: widget.config(background="light blue", activebackground="light blue"))
			self.hash_btns[-1].bind("<ButtonRelease-1>",
			                        lambda event, widget=self.hash_btns[-1]: self.click(event, widget))
			curr_y += 40
		self.window.wait_window()

	def click(self, event, widget):
		self.result_str = widget["text"]
		self.window.destroy()

	def result(self) -> str:
		return self.result_str

def main():
	App()

	# to prevent ongoing hashing from stopping the closing of the app
	psutil.Process(os.getpid()).kill()


if __name__ == "__main__":
	main()
