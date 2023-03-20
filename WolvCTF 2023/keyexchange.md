## keyexchange

```
#!/opt/homebrew/bin/python3

from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
from Crypto.Cipher import AES

n = getPrime(512)

s = getPrime(256)

a = getPrime(256)
# n can't hurt me if i don't tell you
print(pow(s, a, n))
b = int(input("b? >>> "))

secret_key = pow(pow(s, a, n), b, n)

flag = open('/flag', 'rb').read()

key = long_to_bytes(secret_key)
enc = strxor(flag + b'\x00' * (len(key) - len(flag)), key)
print(enc.hex())
```
cukup input b = 1 maka `secret_key = pow(s,a,n)`, sehingga kita hanya perlu melakukan `strxor(enc, pow(s,a,n))` saja.
```
== proof-of-work: disabled ==
278959578473535544583121308438016108719868858450069441387438003415119225406623824663506053283768701756055364347686940239674248847037602493881175105418381
b? >>> 1
7230f2cf7974acd16598584455c798b7290e8c73cb83021b6b8f9f4f5c0be7269ca07048daf4f482435c4584713463e126a3ea01fb79ee405925666ba0b1348d
```
berikut script solvernya:
```
from Crypto.Util.number import *
from Crypto.Util.strxor import strxor

secret_key = long_to_bytes(278959578473535544583121308438016108719868858450069441387438003415119225406623824663506053283768701756055364347686940239674248847037602493881175105418381)
enc = bytes.fromhex('7230f2cf7974acd16598584455c798b7290e8c73cb83021b6b8f9f4f5c0be7269ca07048daf4f482435c4584713463e126a3ea01fb79ee405925666ba0b1348d')

print(strxor(enc, secret_key))
```
flag = `wctf{m4th_1s_h4rd_but_tru5t_th3_pr0c3ss}`
