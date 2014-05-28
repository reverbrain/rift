#!/usr/bin/python

import requests
import hmac
import hashlib
import urlparse
import urllib
import argparse

def generate_signature(key, method, url, headers=None):
    parsed_url = urlparse.urlparse(url)
    queries = urlparse.parse_qsl(parsed_url.query)
    queries.sort()
    text = ''
    text += method + '\n'
    text += parsed_url.path
    if len(queries) > 0:
        text += '?' + urllib.urlencode(queries)
    text += '\n'
    if headers:
        headers = map(lambda x: (x[0].lower(), x[1]), headers.iteritems())
        headers = filter(lambda x: x[0].startswith('x-ell-'), headers)
        headers.sort()

        for header in headers:
            text += header[0] + ':' + header[1] + '\n'

    return hmac.new(key, text, hashlib.sha512).hexdigest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send request to rift.')
    parser.add_argument('url', metavar='URL', help='Url for processing')
    parser.add_argument('--file', dest='file', action='store', default=None, help='File to send with POST request')
    parser.add_argument('--user', dest='user', action='store', default=None, help='Token owner to sign request')
    parser.add_argument('--token', dest='token', action='store', default=None, help='Secure token to sign request')
    args = parser.parse_args()

    headers = {}
    if args.token and args.user:
        headers['Authorization'] = 'riftv1 {0}:{1}'.format(args.user, generate_signature(args.token, 'POST' if args.file else 'GET', args.url))
    elif args.token or args.user:
		raise Exception('Both --user and --token must be specified at the same time')

    if not args.file:
        r = requests.get(args.url, headers=headers)
    else:
        with open(args.file) as f:
            data = f.read()
            r = requests.post(args.url, data, headers=headers)

    print r.status_code
    print r.content