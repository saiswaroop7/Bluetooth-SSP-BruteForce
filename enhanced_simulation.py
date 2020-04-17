"""This is a simulation of the brute-force attack on the enhanced passkey entry protocol. We generate random DHKey
values for every SSP session and calculate r*. Depending on the value of variable "no", we set the known number of
bits."""

import binascii
import hashlib
import hmac
import os
import random
import time
from statistics import mean

start_time = time.time()
# For simplicity we are using the passkey to generate r* in every session. However, ideally the attacker must input
# obtained r* bits and the random integers n' for every session.
"""datasets sample 
PKax = "2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
PKbx = "f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc"
"""
n = [0] * 20
no = 4
x = [0] * no
y = [0] * no
tmp = 0


def firstbrute(n, dhkey, passwords):
    count = 0
    dhkey_bin = str(bin(int(dhkey, 16)))
    dhkey_bin = dhkey_bin[2:]
    dhkey_bin = dhkey_bin.zfill(256)
    print("DHKEY: " + str(dhkey))
    msg = bytes(pas[2:22], "utf-8")
    key = bytes(dhkey_bin, "utf-8")
    h = hmac.new(key, msg, hashlib.sha256)
    hexdat = h.hexdigest()
    c = str(bin(int(hexdat, 16)))
    print("Binary 20-bit Passkey: " + pas[2:22].zfill(20))
    c = c[2:]
    c = c.zfill(256)
    print(c)
    for i in range(0, no):
        y[i] = c[n[i]]
    print("Known r*: " + str(y[:no]))
    # Brute Force
    for i in range(0, 1000000):
        passbrute = str(i)
        if (len(passbrute) < 6):
            passbrute = passbrute.zfill(6)
        passbrute = int(passbrute)
        pasb = str(bin(passbrute))
        msg_brute = bytes(pasb[2:22], "utf-8")
        key_brute = bytes(dhkey_bin, "utf-8")
        hb = hmac.new(key_brute, msg_brute, hashlib.sha256)
        hexdat_brute = hb.hexdigest()
        cb = str(bin(int(hexdat_brute, 16)))
        cb = cb[2:]
        cb = cb.zfill(256)
        for i in range(0, no):
            x[i] = cb[n[i]]
        if x == y:
            passwords[count] = passbrute
            count = count + 1
    passwords = passwords[:count]
    count = count - 1
    print("No. of Potential Passkeys: " + str(len(passwords)))
    return passwords, count


def conbrute(count, n, dhkey, passwords):
    # Initialise Parameters
    newcount = 0
    for i in range(0, 20):
        n[i] = random.randint(0, 255)
    dhkey_bin = str(bin(int(dhkey, 16)))
    dhkey_bin = dhkey_bin[2:]
    dhkey_bin = dhkey_bin.zfill(256)
    msg = bytes(pas[2:22], "utf-8")
    key = bytes(dhkey_bin, "utf-8")
    h = hmac.new(key, msg, hashlib.sha256)
    hexdat = h.hexdigest()
    c = str(bin(int(hexdat, 16)))
    c = c[2:]
    c = c.zfill(256)
    print("Binary 20-bit Passkey: " + pas[2:22].zfill(20))
    print("Known r*: " + c[:no])
    for i in range(0, no):
        y[i] = c[n[i]]

    # Brute Force Consecutive ssp session
    for i in range(count):
        passbrute = str(passwords[i])
        if (len(passbrute) < 6):
            passbrute = passbrute.zfill(6)
        passbrute = int(passbrute)
        pasb = str(bin(passbrute))
        msg_brute = bytes(pasb[2:22], "utf-8")
        key_brute = bytes(dhkey_bin, "utf-8")
        hb = hmac.new(key_brute, msg_brute, hashlib.sha256)
        hexdat_brute = hb.hexdigest()
        cb = str(bin(int(hexdat_brute, 16)))
        cb = cb[2:]
        cb = cb.zfill(256)
        for i in range(0, no):
            x[i] = cb[n[i]]
        if x == y:
            passwords[newcount] = passbrute
            newcount = newcount + 1
    return passwords, newcount


passwords = [0] * 1000000
passkey = str(random.randint(1, 1000000))
for i in range(0, 20):
    n[i] = random.randint(0, 255)
print(n)
if (len(passkey) < 6):
    passkey = passkey.zfill(6)
pas = str(bin(int(passkey)))
print("Passkey:" + pas[2:22])
print("Decimal passkey: " + str(passkey))
# First Brute Force
dhkey = binascii.b2a_hex(os.urandom(32))
passwords, count = firstbrute(n, dhkey, passwords)
passwords = passwords[:count]
tmp = tmp + 0.5
print("First brute: " + str(count))

while (count != 1):
    for i in range(0, 20):
        n[i] = random.randint(0, 255)
    dhkey = binascii.b2a_hex(os.urandom(32))
    print("DHKEY: " + str(dhkey))
    tmp = tmp + 0.5
    passwords, count = conbrute(count, n, dhkey, passwords)
    passwords = passwords[:count]
    if count == 0:
        print(n)
        print("err")
        break
    print("No. of Potential Passkeys: " + str(len(passwords)))

print("Number of SSP sessions required: " + str(tmp))
print("Correct Passkey: " + str(passwords[count - 1]))
print(passwords)
print("Number of Known Bits:" + str(no))
print("--- %s seconds ---" % (time.time() - start_time))
