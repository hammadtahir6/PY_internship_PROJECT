import hashlib #is used for hashing the password
import requests #use to send request 

def password_breach_check(password): #function 
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"API Error: {response.status_code}")
    
    hashes = response.text.splitlines() #it is uses to split the lines we got from the api

    for line in hashes: #for loop used to see if password leaked or not
        h_suffix, count = line.split(':')
        if h_suffix == suffix:
            return int(count)

    return 0

user_password = input("Enter the password: ")
breaches = password_breach_check(user_password)

if breaches:
    print(f"This password was found in {breaches} breaches! Please change it.")
else:
     print("This password was NOT found in any known breaches.")
