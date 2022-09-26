from blake3 import blake3
from hashlib import sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b, md5
from zlib import crc32
import os
import sys
from tkinter import *


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

def main():
	root = Tk()
	root.resizable(False, False)
	root.title("F-Hasher")
	root.geometry(f"500x500+{root.winfo_screenwidth() // 2 - 250}+{root.winfo_screenheight() // 2 - 250}")
	root.iconbitmap(resource_path())


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
