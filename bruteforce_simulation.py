"""This is a simulation of the brute-force attack on the SM passkey entry protocol. We generate random DHKey,
Na0 and Nb0 values for every SSP session and calculate r*. Depending on the value of variable "n1", we set the known
number of bits. The attack runs 50 times and calculate average time it takes to guess the correct passkey for one
instance. """

import binascii
import hashlib
import hmac
import os
import random
import time
from statistics import mean

start_time = time.time()
# For simplicity we are using the passkey to generate r* in every session. However, ideally the attacker must input
# obtained r* bits for every session.
"""datasets sample 
PKax = "2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
PKbx = "f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc"
"""
tmp = 0
count = 0
n1 = 4
ssp = [0] * 50


def firstbrute(dhkey, na, nb, passwords):
    # initialising the values obtained in first SSP session with device A.
    # For our purpose, we are assuming that the attacker has obtained around 7 bits of r* in every SSP session.
    dhkey_bin = str(bin(int(dhkey, 16)))
    na_bin = str(bin(int(na, 16)))
    nb_bin = str(bin(int(nb, 16)))
    print("DHKEY: " + str(dhkey))
    print("na: " + str(na))
    print("nb: " + str(nb))
    dhkey_bin = dhkey_bin[2:]
    na_bin = na_bin[2:]
    nb_bin = nb_bin[2:]
    na_bin = na_bin.zfill(128)
    nb_bin = nb_bin.zfill(128)
    dhkey_bin = dhkey_bin.zfill(256)
    msg = bytes(na_bin + nb_bin + pas[2:22], "utf-8")
    key = bytes(dhkey_bin, "utf-8")
    h = hmac.new(key, msg, hashlib.sha256)
    hexdat = h.hexdigest()
    c = str(bin(int(hexdat, 16)))
    c = c[2:]
    """
    print("Enter known r: ")
    c = str(input())
    n = len(c)
    """
    print("Binary 20-bit Passkey: " + pas[2:22].zfill(20))
    print("Known r*: " + c[:10])
    count = 0

    # Brute Force
    for i in range(0, 1000000):
        passbrute = str(i)
        if len(passbrute) < 6:
            passbrute = passbrute.zfill(6)
        passbrute = int(passbrute)
        pasb = str(bin(passbrute))
        msg_brute = bytes(na_bin + nb_bin + pasb[2:22], "utf-8")
        key_brute = bytes(dhkey_bin, "utf-8")
        hb = hmac.new(key_brute, msg_brute, hashlib.sha256)
        hexdat_brute = hb.hexdigest()
        cb = str(bin(int(hexdat_brute, 16)))
        cb = cb[2:]
        # comparing n1 bits of the r* and bruteforce combination r*
        if cb[:n1] == c[:n1]:
            try:
                passwords[count] = passbrute
            except:
                print("here" + count)
            count = count + 1
    passwords = passwords[:count]
    count = count - 1
    print("No. of Potential Passkeys: " + str(len(passwords)))
    return passwords, count


def conbrute(count, dhkey, na, nb, passwords):
    # Initialising the values obtained in the first SSP session with device B and all the following consecutive SSP
    # sessions performed. For our purpose, we are assuming that the attacker has obtained around 7 bits of r* in
    # every SSP session.
    newcount = 0
    dhkey_bin = str(bin(int(dhkey, 16)))
    na_bin = str(bin(int(na, 16)))
    nb_bin = str(bin(int(nb, 16)))
    dhkey_bin = dhkey_bin[2:]
    na_bin = na_bin[2:]
    nb_bin = nb_bin[2:]
    na_bin = na_bin.zfill(128)
    nb_bin = nb_bin.zfill(128)
    dhkey_bin = dhkey_bin.zfill(256)
    msg = bytes(na_bin + nb_bin + pas[2:22], "utf-8")
    key = bytes(dhkey_bin, "utf-8")
    h = hmac.new(key, msg, hashlib.sha256)
    hexdat = h.hexdigest()
    c = str(bin(int(hexdat, 16)))
    c = c[2:]
    """
    #Enter known r* 
    print("Enter known r: ")
    c = str(input())
    n = len(c)
    """
    print("Binary 20-bit Passkey: " + pas[2:22].zfill(20))
    print("Known r*: " + c[:10])
    i = 0
    # Brute Force Consecutive ssp session
    for i in range(count):
        passbrute = str(passwords[i])
        if len(passbrute) < 6:
            passbrute = passbrute.zfill(6)
        passbrute = int(passbrute)
        pasb = str(bin(passbrute))
        msg_brute = bytes(na_bin + nb_bin + pasb[2:22], "utf-8")
        key_brute = bytes(dhkey_bin, "utf-8")
        hb = hmac.new(key_brute, msg_brute, hashlib.sha256)
        hexdat_brute = hb.hexdigest()
        cb = str(bin(int(hexdat_brute, 16)))
        cb = cb[2:]
        # comparing n1 bits of the r* and bruteforce combination r*
        if cb[:n1] == c[:n1]:
            passwords[newcount] = passbrute
            newcount = newcount + 1
    return passwords, newcount


for x in range(0, 50):
    count = 0
    passwords = [0] * 1000000
    passkey = str(random.randint(1, 1000000))
    if len(passkey) < 6:
        passkey = passkey.zfill(6)
    pas = str(bin(int(passkey)))
    print("Passkey:" + pas[2:22])
    print("Decimal passkey: " + str(passkey))
    # First Brute Force
    dhkey = binascii.b2a_hex(os.urandom(32))
    na = binascii.b2a_hex(os.urandom(16))
    nb = binascii.b2a_hex(os.urandom(16))
    passwords, count = firstbrute(dhkey, na, nb, passwords)
    passwords = passwords[:count]
    tmp = 0.5

    while count != 1:
        dhkey = binascii.b2a_hex(os.urandom(32))
        na = binascii.b2a_hex(os.urandom(16))
        nb = binascii.b2a_hex(os.urandom(16))
        print("DHKEY: " + str(dhkey))
        print("na: " + str(na))
        print("nb: " + str(nb))
        passwords, count = conbrute(count, dhkey, na, nb, passwords)
        passwords = passwords[:count]
        tmp = tmp + 0.5
        if count == 0:
            print("DHKEYerror: " + str(dhkey))
            print("naerr: " + str(na))
            print("nberr: " + str(nb))
            break
        print("No. of Potential Passkeys: " + str(len(passwords)))

    print("Number of SSP sessions required: " + str(tmp))
    ssp[x] = tmp
    print("Correct Passkey: " + str(passwords[count - 1]))

print(ssp)
print("Total Average: " + str(mean(ssp)))
print("Known Bits:" + str(n1))
print("--- %s seconds ---" % (time.time() - start_time))
