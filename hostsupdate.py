#!/usr/bin/python3 -u
''' update domain blocking hosts '''

import requests
import os
import re
import time
import json
import sys

DESTDIR = '/srv/docker/powerdns-recursor/config/blacklist'
CONFIGDIR = '/etc/hostsupdate'

DOMAIN_REGEX = re.compile(
    r'^' +
    r'(?:[A-Za-z0-9-_]{1,63}\.)*' +
    r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)' +
    r'(?:(?!-)[A-Za-z0-9-]{2,63}(?<!-))' +
    r'$'
)

def config_load(path):
    ''' Load json config file '''
    try:
        json_data = json.load(open(path))
    except (OSError, ValueError) as error:
        print('Error: ' + path)
        print(str(error))
        sys.exit(1)
    return json_data

def remote_parse(url):
    ''' Get remote and parse lines into array '''
    try:
        req = requests.get(url, timeout=30)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
        print(str(error))
        return False

    lines = []
    for line in req.text.splitlines():
        line = line.partition('#')[0]
        if line.strip():
            lines.append(line.split()[-1])

    return lines

def domain_encode(domain):
    ''' Encode domain '''
    try:
        encoded = domain.encode('idna').decode('UTF-8')
    except UnicodeError as error:
        print('Encode error: ' + domain)
        print(str(error))
        return False

    if domain != encoded:
        print('Before: ' + domain)
        print('After: ' + encoded)

    return encoded

def domain_validate(domain, invalid, excluded):
    ''' Validate domain '''
    if len(domain) > 253:
        print('Domain too long')
        return False

    if domain in invalid:
        print('Invalid: ' + domain)
        return False

    if not DOMAIN_REGEX.fullmatch(domain):
        print('Regex error: ' + domain)
        return False

    if domain in excluded:
        print('Excluded: ' + domain)
        return False

    return True

def main():
    ''' Main '''

    sources = config_load(os.path.join(CONFIGDIR, 'sources.json'))['sources']
    sources.reverse()
    domains_invalid = config_load(os.path.join(CONFIGDIR, 'invalid.json'))['domains']
    domains_excluded = config_load(os.path.join(CONFIGDIR, 'excluded.json'))['domains']

    while sources:
        for _ in range(len(sources)):
            source = sources.pop()
            print('### ' + source['name'] + ' ###')

            lines = remote_parse(source['url'])
            if not lines:
                sources.insert(0, source)
                continue

            try:
                with open(os.path.join(DESTDIR, source['name']), 'w') as blacklist:
                    for line in lines:
                        domain = domain_encode(line)
                        if not domain:
                            continue
                        if domain_validate(domain, domains_invalid, domains_excluded):
                            blacklist.write(domain + '\n')
            except OSError as error:
                print(str(error))
                sys.exit(1)

        if sources:
            print('Error: Sleeping for 1 hour')
            time.sleep(3600)

if __name__ == '__main__':
    main()
