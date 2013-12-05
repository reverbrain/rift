import requests
import hmac
import hashlib


def check_hash(name, message):
    print("{0}: {1}".format(name, hashlib.sha512(message).hexdigest()))


def generate_signature(key, method, url, headers=None):
    text = ''
    text += method + '\n'
    text += url + '\n'
    if headers:
        headers = map(lambda x: (x[0].lower(), x[1]), headers.iteritems())
        headers = filter(lambda x: x[0].startswith('x-ell-'), headers)
        headers.sort()

        for header in headers:
            text += header[0] + ':' + header[1] + '\n'

    check_hash('key', key)
    check_hash('message', text)

    print '"' + text + '"'

    result = hmac.new(key, text, hashlib.sha512).hexdigest()
    print result
    return result

original_data = "some-text"

r = requests.post("http://localhost:8080/upload?name=123&namespace=qwerty", original_data, headers={
    "Authorization": generate_signature('trello', 'POST', '/upload?name=123&namespace=qwerty'),
    "x-ell-ololo": "trash"
})
print r, r.headers

r = requests.get("http://localhost:8080/get?name=123&namespace=qwerty", headers={
    "Authorization": generate_signature('trello', 'GET', '/get?name=123&namespace=qwerty'),
    "x-ell-ololo": "trash"
})

print r, r.headers

print 'Same data:', (r.content == original_data)
