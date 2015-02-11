#!/usr/bin/python3 -u
''' update domain blocking hosts '''

import requests
import os
import re
import time
import subprocess
import json
import sys

DESTDIR = '/etc/hosts.d'
CONFDIR = '/etc/hostsupdate'

def load_conf(conf_file):
    ''' load json config file '''
    try:
        json_data = json.load(open(os.path.join(CONFDIR, conf_file)))
    except (OSError, ValueError) as error:
        print('Error: ' + conf_file)
        print(str(error))
        sys.exit(1)
    return json_data

def fetch_harvest(url):
    ''' fetch and harvest domains from remote text '''
    try:
        req = requests.get(url, timeout=30)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
        print(str(error))
        return False

    harvested_domains = []
    for line in req.text.splitlines():
        line = line.partition('#')[0]
        if line.strip():
            harvested_domains.append(line.split()[-1])

    return harvested_domains

def encode_check_domain(domain, regex, invalid, excluded):
    ''' encode and check domain '''
    try:
        encoded = domain.encode('idna').decode('UTF-8')
    except UnicodeError as error:
        print('Error: "' + domain + '"')
        print(str(error))
        return False
    if domain != encoded:
        print('Before: "' + domain + '"')
        print('After: "' + encoded + '"')

    if len(encoded) > 253 \
            or encoded in invalid \
            or not regex.fullmatch(encoded):
        print('Invalid: "' + encoded + '"')
        return False

    if encoded in excluded:
        print('Excluded: "' + encoded + '"')
        return False

    return encoded

def main():
    ''' main func '''

    sources = load_conf('sources.json')['sources']
    sources.reverse()
    invalid_domains = load_conf('invalid.json')['domains']
    excluded_domains = load_conf('excluded.json')['domains']

    domain_regex = re.compile(
        r'^' +
        r'(?:[A-Za-z0-9-_]{1,63}\.)*' +
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)' +
        r'(?:(?!-)[A-Za-z0-9-]{2,63}(?<!-))' +
        r'$'
    )

    while sources:
        sources_length = len(sources)
        for _ in range(sources_length):
            source = sources.pop()
            print('### ' + source['name'] + ' ###')

            harvested_domains = fetch_harvest(source['url'])
            if not harvested_domains:
                sources.insert(0, source)
                continue

            try:
                with open(os.path.join(DESTDIR, source['name']), 'w') as hosts_file:
                    for domain in harvested_domains:
                        domain_encoded = encode_check_domain(
                            domain, domain_regex, invalid_domains, excluded_domains
                        )
                        if domain_encoded:
                            hosts_file.write('0.0.0.0 ' + domain_encoded + '\n')
            except OSError as error:
                print(str(error))
                sys.exit(1)

        if sources_length != len(sources):
            try:
                subprocess.check_call([
                    '/usr/bin/pkill',
                    '--uid', 'dnsmasq',
                    '--group', 'dnsmasq',
                    '--exact',
                    '--signal', 'SIGHUP',
                    'dnsmasq',
                ])
            except subprocess.CalledProcessError as error:
                print(str(error))

        if sources:
            print('Connection problem: Sleeping for 1 hour')
            time.sleep(3600)

if __name__ == '__main__':
    main()
