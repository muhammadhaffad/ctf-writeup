## Galois-t is this?

### Mendapatkan `hkey`
nilai `hkey = AES.encypt(b'\0' * 16)` sehingga untuk mendapatkan `hkey` kita harus tahu cara kerja dari fungsi `incr(nonce)`, yaitu pertama mengubah nonce menjadi long kemudian ditambah 1, setelah itu diubah menjadi byte dan diambil 16 byte terakhir. Oleh karena itu kita perlu melakukan encrypt dengan nonce : `'ff' * 16` dan pt : `'00' * 16` karena kita tahu kalau nonce akan di-increment menggunakan fungsi `incr(nonce)` sebanyak `numBlocks + 1` kemudian `enc[:16]` akan digunakan untuk tag dan sisanya (`enc[16:]`) akan digunakan untuk xor `pt` yang menjadi ciphertext nanti, oleh karena itu di sini pt : `'00' * 16` digunakan agar hasil `ct = hkey` tanpa perlu `strxor` untuk mendapatkan `hkey`.

### Membuat Tag
Sebelumnya, tujuan kita yaitu melakukan submit dengan nonce `'00'*15 + '01'`, ct : ciphertext dari 'heythisisasupersecretsupersecret' dalam bentuk hexa dan tag yang akan kita hitung ini. Kita tahu bahwa tag didapatkan dari `strxor(enc[:16], GHASH(hkey, header, ct))`, dan kita sudah mendapatkan `hkey` maka selanjutnya kita perlu mendapatkan `enc[:16]` dan `ct` dalam hal ini `enc[:16] = AES.encrypt(nonce) = AES.encrypt(b'\x00'*15 + b'\x01')` dan `ct = AES.encrypt('heythisisasupersecretsupersecret')`. Jadi, kita perlu melakukan encrypt dengan nonce : `'00' * 16` dan pt : `'00' * 16 + hex(bytes_to_long(b'heythisisasupersecretsupersecret'))[2:]`, karena mode enkripsi AES adalah mode ECB maka kita bisa mendapatkan `enc[:16]` dan `ct` dengan masing-masing `enc[:16] = bytes.fromhex(CT[:32].decode())` dan `ct = bytes.fromhex(CT[32:].decode())` sehingga kita dapat menghitung tag dengan `strxor(enc[:16], GHASH(hkey, header, ct)).hex()`. Setelah itu kita dapat melakukan submit dengan tag yang sudah kita dapatkan.

berikut script solvernya:
```
from Crypto.Util.number import *
from Crypto.Util.strxor import *
from pwn import *

def GF_mult(x, y):
	product = 0
	for i in range(127, -1, -1):
		product ^= x * ((y >> i) & 1)
		x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
	return product

def H_mult(H, val):
	product = 0
	for i in range(16):
		product ^= GF_mult(H, (val & 0xFF) << (8 * i))
		val >>= 8
	return product

def GHASH(H, A, C):
	C_len = len(C)
	A_padded = bytes_to_long(A + b'\x00' * (16 - len(A) % 16))
	if C_len % 16 != 0:
		C += b'\x00' * (16 - C_len % 16)

	tag = H_mult(H, A_padded)

	for i in range(0, len(C) // 16):
		tag ^= bytes_to_long(C[i*16:i*16+16])
		tag = H_mult(H, tag)

	tag ^= bytes_to_long((8*len(A)).to_bytes(8, 'big') + (8*C_len).to_bytes(8, 'big'))
	tag = H_mult(H, tag)

	return tag

header = b'WolvCTFCertified'
	
r = remote('galois.wolvctf.io', 1337)

def encrypt(IV, pt):
	r.sendlineafter('>', b'1')
	r.sendlineafter('>', IV)
	r.sendlineafter('>', pt)
	r.recvuntil(b':')
	CT = r.recvuntil(b'\n')
	r.recvuntil(b':')
	TAG = r.recvuntil(b'\n')
	return (CT.strip(),TAG.strip())

def submit(IV, ct, tag):
	r.sendlineafter('>', b'2')
	r.sendlineafter('>', IV)
	r.sendlineafter('>', ct)
	r.sendlineafter('>', tag)
	r.interactive()

CT, TAG = encrypt(b'ff'*16, b'00'*16)
hkey = int(CT,16)
CT, TAG = encrypt(b'00'*16, b'00'*16 + hex(bytes_to_long(b'heythisisasupersecretsupersecret'))[2:].encode())
enc = bytes.fromhex(CT[:32].decode())
ct = bytes.fromhex(CT[32:].decode())
tag = strxor(enc, long_to_bytes(GHASH(hkey, header, ct))).hex()
submit(b'00'*15+b'01',CT[32:],tag.encode())
```

flag = `wctf{th13_sup3r_s3cr3t_13nt_v3ry_s3cr3t}`
