import threading
from subscraper.support import get_request

class SubModule(threading.Thread):
    name = 'threatcrowd'
    description = "Threadcrowd.org subdomain enumeration."
    author = '@m8r0wn'
    groups = ['all', 'scrape']
    args = {}

    def __init__(self, args, target, print_handler):
        threading.Thread.__init__(self)
        self.daemon = True
        self.handler = print_handler
        self.target = target
        self.timeout = args.timeout

    def run(self):
        link = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}".format(self.target)
        try:
            resp = get_request(link, self.timeout)
            if resp.text and resp.status_code == 200:
                for sub in resp.json()['subdomains']:
                    self.handler.sub_handler({'Name': sub, 'Source': self.name})
        except:
            pass