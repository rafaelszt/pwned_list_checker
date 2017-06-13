import requests
import sys
import time
import getopt
import json


PWNED_BREACH_API_URL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s"
PWNED_BREACH_SHORT_API_URL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s?truncateResponse=true"
PWNED_PASTE_API_URL = "https://haveibeenpwned.com/api/v2/pasteaccount/%s"


def load_file(dir):
    # Load a file and returns the contents as a list
    try:
        with open(dir, 'r') as f:
            lines = f.read().splitlines()
    except IOError:
        print ("File not found")
        sys.exit(2)

    f.close()
    return lines


class InvalidEmail(Exception):
    pass


def response(req):
    # We have something
    if req.status_code == 200:
        return req.json()

    # Invalid input
    elif req.status_code == 400:
        raise InvalidEmail("Invalid Email address")
        return []

    # Email has not been PWNED
    elif req.status_code == 404:
        return []

    # To many requests, slowing down
    elif req.status_code == 429:
        raise Exception('ToManyRequests')


def check_breach(email, long_version=False):
    req = ''
    if long_version:
        req = requests.get(PWNED_BREACH_API_URL % email)
    else:
        req = requests.get(PWNED_BREACH_SHORT_API_URL % email)

    try:
        r = response(req)

    except:
        retry_after = int(req.headers['Retry-After'])
        time.sleep (retry_after + 0.1)
        r = check_breach(email, long_version)

    return r


def check_paste(email):
    req = requests.get(PWNED_PASTE_API_URL % email)

    try:
        r = response(req)

    except:
        retry_after = int(req.headers['Retry-After']) / 1000
        time.sleep (retry_after + 0.1)
        r = check_paste(email)

    return r


def mail_list(list, long_version):
    pwned_list = []

    for mail in list:
        pwned = check_breach(mail, long_version)

        # Did the email have any leaks?
        if (len(pwned) > 0):
            pwned_list.append(pwned)

        # Let's not abuse the API
        time.sleep(1.5)

    return pwned_list


def single_mail(mail):
    pwned = check_breach(mail, False)

    if len(pwned) > 0:
        return pwned

    return []


def print_json(list):
    for l in list:
        print (json.dumps(list, sort_keys=False,
                          indent=4, separators=None))
        print()


def show_options():
    print ("pypwned.py -l <inputfile>")
    print ("pypwned.py -s <emailaddress>\n")
    print ("-l, --list 'file_name'")
    print ("-s, --single 'mail_address'")


def main(argv):
    pwned_mails = []

    try:
        opts, args = getopt.getopt(argv,"hl:s:",["list=","single="])

    except getopt.GetoptError:
        show_options()
        sys.exit(2)

    if opts == []:
        show_options()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            show_options()
            sys.exit()

        elif opt in ('-l', '--list'):
            if len(mail_list(load_file(arg), False)) > 0:
                pwned_mails.append(arg)

        elif opt in ('-s', '--single'):
            if len(single_mail(arg)) > 0:
                pwned_mails.append(arg)

    # if we got some pwned users, get more info on then
    if pwned_mails is not []:
        print(pwned_mails)
        pwned_mails = mail_list(pwned_mails, True)
        print_json(pwned_mails)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(1)
