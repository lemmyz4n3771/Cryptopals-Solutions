from flask import Flask, request
from Crypto.Random import get_random_bytes
import time
from cryptopals import hmac 


app = Flask(__name__)
# Generate a key at the start of the server
KEY = get_random_bytes(16)


@app.route('/test')
def verifySignature():
    # Extract params
    file = request.args.get('file')
    signature = request.args.get('signature')

    # Determine HMAC from KEY
    mac = hmac(key=KEY, message=file.encode()).hex()

    # compare to signature
    # Note: Even at 50 ms and multiprocessing, this takes a long time 
    # to complete as the HMAC value grows longer
    isSigGood = insecure_compare(mac, signature, sleepTime=0.05)

    if isSigGood:
        return 'valid signature', 200
    else:
        return 'invalid signature', 500

def insecure_compare(mac1: str, mac2: str, sleepTime: float) -> bool :
    # implements the == operation by doing byte-at-a-time comparisons with early exit 
    # (ie, return false at the first non-matching byte) The early exit is the vulnerablity here
    for i in range(min(len(mac1), len(mac2))):
        if mac1[i] != mac2[i]:
            return False
        time.sleep(sleepTime)
    # if lengths are not equal, by definition, we've reached a byte that is not the same
    if len(mac1) != len(mac2): 
        return False
    return True

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=9000)