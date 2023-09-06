import cryptopals

test1 = b"ICE ICE BABY\x04\x04\x04\x04"
test2 = b"ICE ICE BABY\x01\x02\x03\x04"

print(cryptopals.isPKCS7Padded(test1))
print(cryptopals.isPKCS7Padded(test2))