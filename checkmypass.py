
#* This program receives multiple arguments and then converts those arguments into hashes through SHA1 algorithm
#* Then it sends the first 5 char (in order to improve security) of the hash converted to an API called pwnedpasswords
#* Which returns passwords/ hashes with the same first 5 chars with their counts of how many times they have been breached
#* Then this prog matches all the returned hashes with the hash that we created earlier and prints how many times the password was hacked.

import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + str(query_char)
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code}, check the API and try again!')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h,count in hashes:
        if(h == hash_to_check):
            return count
    return 0    

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_char, tail = sha1password[0:5], sha1password[5:]
    response = request_api_data(first_5_char)
    return get_password_leaks_count(response, tail)



def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count != 0:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return('All Done!')        

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


