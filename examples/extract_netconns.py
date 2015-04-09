#!/usr/bin/env python
import ConfigParser
import argparse
import logging

import requests
from progressbar import *
from collections import defaultdict
import os
import sys

try:
    import cbapi2
except:
    import sys

    sys.path.append('..')
    import cbapi2


def main():
    parser = argparse.ArgumentParser(description="Grab netconn data from Cb server")
    parser.add_argument('-t', '--apitoken', nargs=1, help='API token - only required if not known')
    parser.add_argument('-v', action='store_true', dest='verbose', help='Enable verbose debugging messages',
                        default=False)
    parser.add_argument('-o', action='store_true', dest='open_in_excel', help='Open the csv file after generation',
                        default=False)
    parser.add_argument('--config', default='cbapi.cfg', help='Path to configuration file')

    parser.add_argument('-c', '--customer', nargs=1, help='Customer name')

    results = parser.parse_args()

    if results.verbose:
        l = logging.getLogger('co.redcanary')
        l.setLevel(logging.DEBUG)
    else:
        l = logging.getLogger('co.redcanary.eventcsv')
        l.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    l.addHandler(ch)

    if os.path.exists(results.config):
        config = ConfigParser.ConfigParser()
        config.read(results.config)
    else:
        l.error("No configuration file found, exiting")
        return 1

    return grab_netconns(results, config)

def grab_netconns(opts, config):
    hostnames = defaultdict(int)
    ipaddrs = defaultdict(int)
    filter_string = 'netconn_count:[1 TO *]'

    widgets = ['Process Docs: ', Percentage(), ' ', Bar(),
       ' ', ETA()]
    progress = ProgressBar(widgets=widgets).start()

    c = cbapi2.CbApi2(config.get(opts.customer[0], 'cb_url'),
                      config.get(opts.customer[0], 'cb_token'),
                      ssl_verify=False)

    q = c.process_search(filter_string)

    for doc in q:
        for netconn in doc.netconns:
            if netconn.dns: hostnames[netconn.dns] += 1
        ipaddrs[netconn.ipaddr] += 1

    for hostname in hostnames:
        print '%s,%d' % (hostname, hostnames[hostname])

    for ipaddr in ipaddrs:
        print '%s,%d' % (ipaddr, ipaddrs[ipaddr])

if __name__ == '__main__':
    sys.exit(main())
