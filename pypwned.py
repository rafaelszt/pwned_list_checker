import requests
import sys
import time
import getopt


PWNED_BREACH_API_URL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s"
PWNED_BREACH_SHORT_API_URL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s?truncateResponse=true"
PWNED_PASTE_API_URL = "https://haveibeenpwned.com/api/v2/pasteaccount/%s"


class ProgressBar():
    previous_value = -1

    def __init__(self):
        self.toolbar_width = 100

        sys.stdout.write("[%s]" % (" " * self.toolbar_width))
        sys.stdout.flush()
        sys.stdout.write("\b" * (self.toolbar_width+1)) # return to start of line, after '['


    def update(self, value):
        if (value != self.previous_value):
            self.previous_value = value
            sys.stdout.write("-")
            sys.stdout.flush()


    def finish():
        sys.stdout.write("\n")


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

class ToManyRequests(Exception):
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
        raise ToManyRequests("To many requests")

    else:
        print ("\
               Something went wrong.\n\
               Try again later. \n\
               Or right now, it's up to you.")
        sys.exit(2)


def check_breach(email, long_version=False):
    req = ''

    if long_version:
        req = requests.get(PWNED_BREACH_API_URL % email)

    else:
        req = requests.get(PWNED_BREACH_SHORT_API_URL % email)

    try:
        r = response(req)
    except ToManyRequests:
        print ("Too many requests, waiting a few seconds before trying again.")
        time.sleep (int(req.headers['Retry-After']) + 0.1)
        r = check_breach(email, long_version)
    except:
        sys.exit(2)

    return r


def check_paste(email):
    req = requests.get(PWNED_PASTE_API_URL % email)

    try:
        r = response(req)

    except ToManyRequests:
        time.sleep (int(req.headers['Retry-After']) + 0.1)
        r = check_paste(email)
    except:
        sys.exit(2)

    return r


def single_mail(mail, long_version):
    breach = False
    paste = False

    pwned = check_breach(mail, long_version)
    if len(pwned) > 0:
        breach = True

    pwned = check_paste(mail)
    if len(pwned) > 0:
        paste = True

    return breach, paste

def mail_list(list, long_version):
    breach_list = []
    paste_list = []

    total_processed = 0
    progress_bar = ProgressBar()

    for mail in list:
        breach, paste = single_mail(mail, long_version)

        # Did the email have any leaks?
        if (breach):
            breach_list.append(mail)

        # What about in the pastes?
        if (paste):
            paste_list.append(mail)

        # We can't forget about our progress bar
        total_processed += 1
        progress_bar.update(int(total_processed / len(list)*100))

        # Let's not abuse the API
        time.sleep(1.5)

    return breach_list, paste_list


def show_options():
    print ("pypwned.py -l <inputfile>")
    print ("pypwned.py -s <emailaddress>\n")
    print ("-l, --list 'file_name'")
    print ("-s, --single 'mail_address'")


def main(argv):
    pwned_mails = []
    breach_list = []
    paste_list = []

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
            mails = load_file(arg)
            breach_list, paste_list = mail_list(mails, False)

            break

        elif opt in ('-s', '--single'):
            breach_list, paste_list = single_mail(arg, False)
            if breach_list:
                breach_list = arg
            if paste_list:
                paste_list = arg

            break

    if len(breach_list) > 0:
        print ("Emails with a breach:")
        print (breach_list)
    if len(paste_list) > 0:
        print ("Emails in a paste:")
        print (paste_list)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(1)
