#!/usr/bin/python3 -u
''' Parse domain lists into blacklists '''

from collections import OrderedDict
import os
import re
import sys
import time

import requests
import yaml

PATH_DESTDIR = sys.argv[1]

CONFIG = yaml.load(
    open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config.yaml')),
    Loader=yaml.CLoader
)

DOMAIN_REGEX = re.compile(
    r'^'
    r'(?:(?!-)[A-Za-z0-9-_]{1,63}(?<!-)\.)+'
    r'(?:(?!-)[A-Za-z0-9-]{2,63}(?<!-)\.?)'
    r'$'
)


def remote_parse(url):
    ''' Get remote and parse lines into array '''
    try:
        request = requests.get(url,
                               timeout=(CONFIG['Timeout']['Connect'], CONFIG['Timeout']['Read']))
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as error:
        print(str(error))
        return None

    lines = []
    for line in request.text.splitlines():
        line = line.partition('#')[0]
        if line.strip():
            lines.append(line.split()[-1])

    return sorted(set(lines))


def domain_encode(domain):
    ''' Encode domain '''
    try:
        encoded = domain.encode('idna').decode('UTF-8')
    except UnicodeError as error:
        print('Encode error: {0:s}\n{1:s}'.format(domain, str(error)))
        return None

    if domain != encoded:
        print('Before: {0:s}'.format(domain))
        print('After: {0:s}'.format(encoded))

    return encoded


def domain_validate(domain):
    ''' Validate domain '''
    if len(domain) > 253:
        print('len(domain) > 253: {0:s}'.format(domain))
        return False

    if not DOMAIN_REGEX.fullmatch(domain):
        print('Regex error: {0:s}'.format(domain))
        return False

    if domain in CONFIG['Exclude']:
        print('Excluded: {0:s}'.format(domain))
        return False

    return True


def main():
    ''' Main '''
    if not os.path.exists(PATH_DESTDIR) and os.path.isdir(PATH_DESTDIR):
        print('destination path error: {0:s}'.format(PATH_DESTDIR))
        sys.exit(1)

    sources = OrderedDict(sorted(CONFIG['Sources'].items(), key=lambda source: source[0]))

    while sources:
        for source, url in sources.copy().items():
            print('Source: {0:s}'.format(source))

            lines = remote_parse(url)
            if lines is None:
                continue
            del sources[source]
            if not lines:
                print('Empty list: {0:s}'.format(source))
                continue

            with open(os.path.join(PATH_DESTDIR, source), 'w') as blacklist:
                for line in lines:
                    domain = domain_encode(line)
                    if not domain:
                        continue
                    if domain_validate(domain):
                        blacklist.write(domain + '\n')

        if sources:
            print('Sleeping for {0:d} seconds'.format(CONFIG['Sleep']))
            time.sleep(CONFIG['Sleep'])

if __name__ == '__main__':
    main()
