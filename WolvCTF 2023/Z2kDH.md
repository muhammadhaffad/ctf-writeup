## Z2kDH

Z2kDH.py:
```
#!/usr/bin/python3

modulus = 1 << 258

def Z2kDH_init(private_exponent):
	"""
	Computes the public result by taking the generator 5 to the private exponent, then removing the last 2 bits
	private_exponent must be a positive integer less than 2^256
	"""
	return pow(5, private_exponent, modulus) // 4

def Z2kDH_exchange(public_result, private_exponent):
	"""
	Computes the shared secret by taking the sender's public result to the receiver's private exponent, then removing the last 2 bits
	public_result must be a non-negative integer less than 2^256
	private_exponent must be a positive integer less than 2^256
	"""
	return pow(public_result * 4 + 1, private_exponent, modulus) // 4

alice_private_exponent = int(open('alice_private_exponent.txt').read(), 16)
bob_private_exponent = int(open('bob_private_exponent.txt').read(), 16)

alice_public_result = Z2kDH_init(alice_private_exponent)
bob_public_result = Z2kDH_init(bob_private_exponent)

# These are sent over the public channel:
print(f'{alice_public_result:064x}') # Alice sent to Bob
print(f'{bob_public_result:064x}')   # Bob sent to Alice

alice_shared_secret = Z2kDH_exchange(bob_public_result, alice_private_exponent)
bob_shared_secret = Z2kDH_exchange(alice_public_result, bob_private_exponent)

assert alice_shared_secret == bob_shared_secret # the math works out!

# ...Wait, how did they randomly end up with this shared secret? What a coincidence!
```

output.txt:
```
99edb8ed8892c664350acbd5d35346b9b77dedfae758190cd0544f2ea7312e81
40716941a673bbda0cc8f67fdf89cd1cfcf22a92fe509411d5fd37d4cb926afd
```

Kita dapat melakukan discrete log menggunakan Sage untuk mendapatkan private exponent dari alice. kemudian melakukan exchange dengan public bob dan private exponent alice untuk mendapatkan flag, berikut script yang digunakan:

```
def Z2kDH_exchange(public_result, private_exponent, modulus):
  return int(pow(public_result * 4 + 1, private_exponent, modulus)) // 4
  
n = 1 << 258
#menggeser ke kanan sebanyak 2 bit, karena hasil dari `Z2kDH_init` menghilangkan 2 bit terakhir
alice_pub = (0x99edb8ed8892c664350acbd5d35346b9b77dedfae758190cd0544f2ea7312e81 << 2) + 1
bob_pub = 0x40716941a673bbda0cc8f67fdf89cd1cfcf22a92fe509411d5fd37d4cb926afd

#discrete log
R = Integers(n)
A = R(5)
B = R(alice_pub)
alice_priv = B.log(A)
print(bytes.fromhex(hex(Z2kDH_exchange(bob_pub, alice_priv, n))[2:]))
```

flag: `wctf{P0HL1G_H3LLM4N_$M4LL_pr1M3}`
