#Detects if password has been compromised

import hashlib
import requests

# This function checks if a password has been compromised
def check_pwd(password):
    # Hash the password using the SHA-1 hashing algorithm
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Split the hash into a prefix and suffix
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    # Construct the URL for the "Have I Been Pwned" API using the prefix
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    # Send a GET request to the API to get a list of hashes that match the prefix
    response = requests.get(url)

    # the code will go through the list of hashes and check if the suffix matches
    for line in response.text.splitlines():
        line_prefix, count = line.split(':')
        if line_prefix == suffix:
            # If the suffix matches, return the number of times the password has been exposed
            return int(count)

    # If the suffix does not match, the password has not been exposed
    return 0

# User will enter passcode to check if its compromised
password = input("Please enter a password to check if it has been compromised: ")

# Checks if the password has been exposed
count = check_pwd(password)

if count > 0:
    # If password has been compromised and amount of time
    print(f"The password has been compromised {count} times.")
else:
    # If the password has not been exposed, print a message indicating that it is not compromised
    print("The password has not been compromised!!")