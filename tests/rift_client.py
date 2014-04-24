import requests
import uuid


class Client:
    def __init__(self, option):
        self.base_url = 'http://localhost:8080'
        self.bucket = option.bucket
        if self.bucket:
            self.user = self.generate_user()
            self.directory_user = self.generate_user()
            self.directory_user['key'] = self.bucket
        else:
            self.user = None
            self.directory_user = None

    def generate_user(self):
        return {
            'key': uuid.uuid4().hex,
            'user': uuid.uuid4().hex,
            'token': uuid.uuid4().hex
        }

    def generate_signature(self, method, url, user, headers=None):
        import urlparse
        import urllib
        import hmac
        import hashlib

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

        print "text: '{}'".format(text)

        result = hmac.new(user['token'], text, hashlib.sha512).hexdigest()
        print result, text
        return result

    def generate_url(self, method, url, user, **kwargs):
        import urlparse
        import urllib

        parsed_url = urlparse.urlsplit(url)
        query = parsed_url.query

        if user:
            qs = urlparse.parse_qs(parsed_url.query)
            qs['bucket'] = user['key']
            qs['user'] = user['user']
            query = urllib.urlencode(qs)

        result_url = urlparse.urlunsplit(('http', 'localhost:8080', parsed_url.path, query, parsed_url.fragment))

        if user and 'token' in user:
            headers = kwargs['headers'] if 'headers' in kwargs else {}
            authorization = self.generate_signature(method, result_url, user, headers)
            headers['Authorization'] = authorization
            kwargs['headers'] = headers

        return result_url, kwargs

    def authorized_get(self, url, user, **kwargs):
        fixed_url, fixed_args = self.generate_url('GET', url, user, **kwargs)
        r = requests.get(fixed_url, **fixed_args)
        assert isinstance(r, requests.Response)
        return r

    def authorized_post(self, url, data, user, **kwargs):
        fixed_url, fixed_args = self.generate_url('POST', url, user, **kwargs)
        r = requests.post(fixed_url, data, **fixed_args)
        assert isinstance(r, requests.Response)
        return r

    def get(self, url, **kwargs):
        return self.authorized_get(url, self.user, **kwargs)

    def post(self, url, data, **kwargs):
        return self.authorized_post(url, data, self.user, **kwargs)

    def post_unsafe(self, url, data, **kwargs):
        return self.authorized_post(url, data, None, **kwargs)


class ClientProxy:
    def __init__(self, client, user):
        assert isinstance(client, Client)
        self.client = client
        self.user = user
        self.bucket = client.bucket

    def get(self, url, **kwargs):
        return self.client.authorized_get(url, self.user, **kwargs)

    def post(self, url, data, **kwargs):
        return self.client.authorized_post(url, data, self.user, **kwargs)