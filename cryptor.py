import sys
import getopt
import os
import time
import string
import stdiomask

import tarfile

import base64
import uuid

import struct
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidKey, InvalidTag

compression_method = ""
file_extension = ""
if compression_method != "":
	file_extension = ".tar." + compression_method
else:
	file_extension = ".tar"

output_filename = ''


def get_input(output):
	line = input(output)
	print('Dispatch %s' % line)
	return line

def make_tarfile(source_dir):
	with tarfile.open(source_dir + file_extension, "w:" + compression_method) as tar:
		tar.add(source_dir, arcname=os.path.basename(source_dir))

def decompress(compressed_filename):
	tar = tarfile.open(compressed_filename, "r:" + compression_method)
	tar.extractall()
	tar.close()

def get_key(verbose_pass=False):
	print("Please write your password")

	password1 = stdiomask.getpass()
	password1 = password1.encode()

	# Okey for this application, if this application is used for storring multiple users data or something like that
	# A non static salt should be used to avoid rainbow-table vulnerbilities
	salt = b'u\xcf(\n\xd5\x9c\x05\xffy\x97\x96\xb1@\x1f\rn'

	time1 = time.time()

	kdf = Scrypt(salt = salt, length=32, n = 2**20, r=8, p=1)

	key = base64.urlsafe_b64encode(kdf.derive(password1))
	#key = kdf.derive(password1)

	print("It took ", time.time() - time1, " seconds to generate the key")

	print("Please verify your password")
	password2 = stdiomask.getpass()
	password2 = password2.encode()

	if password2 != password1:
		print("Passwords didn't match")
		exit(-1)

	return key


# <====================== ENCRYPTION =========================>
def encrypt(input_filename, key, block = 1 << 28):
	fernet = Fernet(key)

	encrypted_data = bytes()

	filesize = os.stat(input_filename).st_size
	enc_size = 0

	with open(input_filename, 'rb') as fin:
		while True:
			chunck = fin.read(block)
			if len(chunck) == 0:
				break
			encrypted_chunck = fernet.encrypt(chunck)
			encrypted_data += struct.pack('<I', len(encrypted_chunck))
			encrypted_data += encrypted_chunck
			if len(encrypted_chunck) < block:
				break
			enc_size += len(chunck)
			print("Progress: ", enc_size / filesize)


	return encrypted_data


def run_encryption(folder_to_encrypt, key):
	make_tarfile(folder_to_encrypt)

	encrypted_data = encrypt(folder_to_encrypt + file_extension, key)

	os.remove(folder_to_encrypt + file_extension)

	# Generate random filename
	output_filename = "INFO-" + str(uuid.uuid4())[:13] + ".ngfp"
	while (os.path.exists(output_filename)): # Chances for this happening are astronomically small
		output_filename = "INFO-" + str(uuid.uuid4())[:13] + ".ngfp"

	with open(output_filename, 'wb') as fout:
		fout.write(encrypted_data) # Write the encrypted bytes to the output file



# <====================== DECRYPTION =========================>
def decrypt(input_filename, key):
	fernet = Fernet(key)

	decrypted_data = bytes()

	filesize = os.stat(input_filename).st_size
	dec_size = 0

	with open(input_filename, 'rb') as fin:
		while True:
			size_data = fin.read(4)
			if len(size_data) == 0:
				break
			encrypted_chunk = fin.read(struct.unpack('<I', size_data)[0])
			decrypted_data += fernet.decrypt(encrypted_chunk)
			dec_size += len(encrypted_chunk)
			print('Progress: ', dec_size / filesize)

	return decrypted_data

def run_decryption(file_to_decrypt, key):
	decrypted_data = decrypt(file_to_decrypt, key)

	# Generate random filename
	output_filename = "TEMP-" + str(uuid.uuid4())[:13] + file_extension
	while (os.path.exists(output_filename)): # Chances for this happening are astronomically small
		output_filename = "TEMP-" + str(uuid.uuid4())[:13] + file_extension
	
	with open(output_filename, 'wb') as fout:
		fout.write(decrypted_data) # Write the decrypted bytes to the output file

	decompress(output_filename)

	os.remove(output_filename)


def main(argv):
	filename = ''
	crypt_option = ''

	try:
		opts, args, = getopt.getopt(argv, "hi:m:",["ifile=", "mode="])
	except getopt.GetoptError:
		print('test.py -i <inputfile> -m <crypt mode (decrypt) or (encrypt)>')
		exit(-1)

	# check inputs
	for opt, arg in opts:
		if opt == '-h':
			print('crypter.py -i <folder_to_encrypt or file to decrypt> -m <decrypt or encrypt>')
			exit(-1)
		elif opt in ("-i", "--ifile"):
			filename = arg
			if not os.path.exists(filename):
				print("Not a valid filename")
				exit(-1)
		elif opt in ("-m", "--mode"):
			crypt_option = arg
			if arg != "decrypt" and arg != "encrypt":
				print("not a viable decrypt or encrypt option")
				exit(-1)

	key = get_key()	

	if crypt_option == "encrypt":
		run_encryption(filename, key)
	elif crypt_option == "decrypt":
		run_decryption(filename, key)



if __name__ == "__main__":
	main(sys.argv[1:])