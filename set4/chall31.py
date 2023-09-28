import requests
from multiprocessing import Pool
from time import time

# globals
url = "http://localhost:9000/test?"
file = b"lemmy.txt"

def timingLeakAttack():
    # The idea of this attack is to brute force each hex byte with a number of tests, 
    # recording the time it takes to hear back from the server.  The longer it takes, 
    # the better our guess was. Turn the HMAC into hex so that we have a limited range of values to check for (16)
    mac = ''
    # parallelize execution with Pool
    pool = Pool(processes=4)

    # Length of HMAC as hex is 40, so run 40 times
    for _ in range(40):
        # Make a list of the current mac value, attaching all 16 hex possibilities
        guesses = [mac + hex(x)[2:] for x in range (16)]
        # For each guess, test it
        results = pool.map(testMAC, guesses)

        # Now find the best time and add the hex value associated with it to the current mac
        # Index 0 contains the resulf if we found mac, index 1 contains the averaged time of all tries
        longestTime, deciVal = 0, 0
        for num in range(len(results)):
            if results[num][0]:
                return guesses[num]
            if results[num][1] > longestTime:
                longestTime = results[num][1]
                deciVal = num
        mac += hex(deciVal)[2:]
        print(f"{len(mac)} of 40 found: {mac}")
    return mac

def testMAC(mac: str) -> (bool, float):
    params = {"file":file.decode(), "signature":mac}
    times = []
    # Average 5 tries; you can make this longer, but it already takes a long time
    for i in range(5):
        start = time()
        status_code = requests.get(url, params).status_code
        end = time()
        times.append(end - start)
    foundMac = True if status_code == 200 else False
    return foundMac, average(times)


def average(floats: list) -> float:
    return sum(floats) / len(floats)

def main():
    start = time()
    mac = timingLeakAttack()
    end = time()
    print(f"HMAC found: {mac}\nDuration of attack: {end - start}\n")
    # Example output:
    #  39 of 40 found: 70b8cb9802cb468a459b904b7491cd350d2ce3c
    #  HMAC found: 70b8cb9802cb468a459b904b7491cd350d2ce3c7
    #  Duration of attack: 800.6516540050507
    # That's about 13 minutes


if __name__ == "__main__":
    main()