from copy import deepcopy
import rift_client
import os
import pytest
import json
import hashlib
import uuid


class TestCases:
    @classmethod
    @pytest.fixture(scope = "class", autouse = True)
    def setup(self):
        self.data = os.urandom(1000000 * 30)

    def create_bucket(self, client, flags = 0, command = ''):
        data = {
            'groups': [
                5, 6
            ],
            'acl': [
                {
                    'user': client.user['user'],
                    'token': client.user['token'],
                    'flags': flags
                }
            ]
        }

        r = client.post(command, json.dumps(data))

        assert r.status_code == 200

    @pytest.mark.skipif(not pytest.config.option.bucket,
                        reason="tests are running without buckets")
    def test_update_directory(self, client):
        dir_proxy = rift_client.ClientProxy(client, client.directory_user)
        self.create_bucket(dir_proxy, command='/update-bucket-directory')

    @pytest.mark.skipif(not pytest.config.option.bucket,
                        reason="tests are running without buckets")
    def test_create_bucket(self, client):
        assert isinstance(client, rift_client.Client)

        self.create_bucket(client, command='/update-bucket/' + client.bucket)

    def test_upload(self, client):
        assert isinstance(client, rift_client.Client)
        r = client.post("/upload/name", self.data)
        assert r.status_code == 200

    def test_get(self, client):
        assert isinstance(client, rift_client.Client)
        r = client.get("/get/name")

        assert r.status_code == 200
        assert len(r.content) == len(self.data)
        assert r.content == self.data

    @pytest.mark.skipif(not pytest.config.option.bucket,
                        reason="tests are running without buckets")
    @pytest.mark.parametrize('flags, write_noauth_status, write_auth_status, read_noauth_status, read_auth_status', [
        (0, 401, 200, 401, 200),
        (1, 401, 200, 200, 200),
        (2, 200, 200, 200, 200),
        (3, 200, 200, 200, 200),
    ])
    def test_acl(self, client, flags, write_noauth_status, write_auth_status, read_noauth_status, read_auth_status):
        assert isinstance(client, rift_client.Client)

        user = client.generate_user()
        noauth_user = deepcopy(user)
        del noauth_user['token']

        bucket_proxy = rift_client.ClientProxy(client, user)

        self.create_bucket(bucket_proxy, flags=flags, command='/update-bucket/' + client.bucket)

        noauth_data = uuid.uuid4().hex
        auth_data = uuid.uuid4().hex

        auth_proxy = rift_client.ClientProxy(client, user)
        noauth_proxy = rift_client.ClientProxy(client, noauth_user)

        r = noauth_proxy.post('/upload/noauth', noauth_data)
        assert r.status_code == write_noauth_status

        r = auth_proxy.post('/upload/auth', auth_data)
        assert r.status_code == write_auth_status

        r = auth_proxy.get('/get/noauth')
        assert r.status_code == (200 if write_noauth_status == 200 else 404)
        if r.status_code == 200:
            assert r.content == noauth_data

        r = noauth_proxy.get('/get/auth')
        assert r.status_code == read_noauth_status
        if r.status_code == 200:
            assert r.content == auth_data

        r = auth_proxy.get('/get/auth')
        assert r.status_code == read_auth_status
        if r.status_code == 200:
            assert r.content == auth_data

    def test_ping(self, client):
        assert isinstance(client, rift_client.Client)
        r = client.get("/ping/")
        assert r.status_code == 200

    def test_echo(self, client):
        assert isinstance(client, rift_client.Client)
        data = "test-data"
        r = client.post("/echo/", data, headers={ "X-UNIQUE-HEADER": "some-value" })
        assert r.status_code == 200
        assert r.headers["X-UNIQUE-HEADER"] == "some-value"
        assert r.content == data

    def test_delete(self, client):
        assert isinstance(client, rift_client.Client)
        
        name = "delete-test"
        r = client.post("/upload/" + name, self.data)
        assert r.status_code == 200
        r = client.get("/get/" + name)
        assert r.status_code == 200
        r = client.post("/delete/" + name, self.data)
        assert r.status_code == 200
        r = client.get("/get/" + name)
        assert r.status_code == 404

    def test_download_info(self, client):
        assert isinstance(client, rift_client.Client)
        r = client.get("/download-info/name")

        assert r.status_code == 200

        info = r.json()

        name_prefix = (client.user['key'] + '\0') if client.user else ""
        assert info['id'] == hashlib.sha512(name_prefix + "name").hexdigest()
        assert info['size'] == len(self.data)
        assert info['offset-within-data-file'] > 0
        assert abs(float(info['time']) - float(info['mtime']['time-raw'])) < 10
        assert len(info['csum']) == 128

        if client.bucket:
            r = client.get('/redirect/name', allow_redirects=False)
            assert r.status_code == 302
            assert info['url'] == r.headers['Location']

        with open(info['filename'], 'r') as f:
            f.seek(info['offset-within-data-file'])
            assert f.read(info['size']) == self.data

    @pytest.mark.parametrize('begin, end, status_code', [
        ('0', '100', 206),
        ('100', '200', 206),
        ('100', '1000', 206),
        ('100', '20000000', 206),
        ('', '5', 206),
        ('', '20000000', 206),
        ('60000000', '', 416)
    ])
    def test_single_range(self, client, begin, end, status_code):
        range_header = "bytes={0}-{1}".format(begin, end)

        assert isinstance(client, rift_client.Client)
        r = client.get("/get/name", headers={ 'Range': range_header })

        assert r.status_code == status_code
        if status_code != 206:
            return

        assert r.headers['Accept-Ranges'] == 'bytes'

        start = 0
        finish = len(self.data) - 1

        if len(begin) == 0:
            start = len(self.data) - int(end)
        elif len(end) == 0:
            start = int(begin)
        else:
            start = int(begin)
            finish = int(end)

        range_header_result = 'bytes {0}-{1}/{2}'.format(start, finish, len(self.data))
        assert r.headers['Content-Range'] == range_header_result
        assert r.headers['Content-Length'] == str(finish + 1 - start)

        ideal_data = self.data[start:finish + 1]
        assert len(r.content) == len(ideal_data)
        assert r.content == ideal_data

    @pytest.mark.skipif(not pytest.config.option.bucket,
                        reason="tests are running without buckets")
    @pytest.mark.parametrize('name', [
        ('list')
    ])
    def test_list_bucket(self, client, name):
        assert isinstance(client, rift_client.Client)

        r = client.get('/' + name)

        assert r.status_code == 200

        list_info = r.json()
        assert 'indexes' in list_info
        indexes = list_info['indexes']
        assert len(indexes) == 1

        r = client.get("/download-info/name")

        assert r.status_code == 200

        info = r.json()

        print list_info
        print info

        assert indexes[0]['id'] == info['id']
        assert indexes[0]['key'] == 'name'
        assert 'timestamp' in indexes[0]
        assert 'time_seconds' in indexes[0]


    @pytest.mark.skipif(not pytest.config.option.bucket,
                        reason="tests are running without buckets")
    def test_list_bucket_directory(self, client):
        assert isinstance(client, rift_client.Client)

        bucket_proxy = rift_client.ClientProxy(client, client.directory_user)

        r = bucket_proxy.get('/list-bucket-directory')

        assert r.status_code == 200

        buckets_list = r.json()
        assert len(buckets_list['indexes']) == 5
        assert client.user['key'] in [x['key'] for x in buckets_list['indexes']]

    @pytest.mark.skipif(not pytest.config.option.bucket,
                        reason="tests are running without buckets")
    def test_delete_bucket(self, client):
        assert isinstance(client, rift_client.Client)

        bucket_proxy = rift_client.ClientProxy(client, client.directory_user)

        user = client.generate_user()
        subbucket_proxy = rift_client.ClientProxy(client, user)

        self.create_bucket(subbucket_proxy, flags=0, command='/update-bucket/' + client.bucket)

        r = bucket_proxy.get('/list-bucket-directory')

        assert r.status_code == 200

        buckets_list = r.json()
        assert user['key'] in [x['key'] for x in buckets_list['indexes']]

        r = subbucket_proxy.post('/delete-bucket', '')

        assert r.status_code == 200

        r = bucket_proxy.get('/list-bucket-directory')

        assert r.status_code == 200

        buckets_list = r.json()
        assert user['key'] not in [x['key'] for x in buckets_list['indexes']]

    @pytest.mark.parametrize('view', [
        ('id-only'),
        ('extended')
    ])
    def test_indexes(self, client, view):
        assert isinstance(client, rift_client.Client)

        data = uuid.uuid4().hex

        r = client.post('/upload/index-test', data)
        assert r.status_code == 200

        indexes = [
            "fast",
            "elliptics",
            "distributive",
            "reliable",
            "falt-tolerante"
        ]

        update_data = {
            'indexes': {
            }
        }

        for index in indexes:
            update_data['indexes'][index] = index

        print "'{0}'".format(json.dumps(update_data))
        print len(json.dumps(update_data))

        r = client.get("/download-info/index-test")

        assert r.status_code == 200

        info = r.json()

        r = client.post('/update/index-test', json.dumps(update_data))
        assert r.status_code == 200

        find_data = {
            'view': view,
            'type': 'or',
            'indexes': indexes
        }

        r = client.post('/find/', json.dumps(find_data))
        assert r.status_code == 200

        find_result = r.json()

        assert info['id'] in find_result
        find_indexes = find_result[info['id']]
        assert find_indexes['indexes'] == update_data['indexes']

        print r.content

        if view == 'extended':
            assert 'data-object' in find_indexes
            data_object = find_indexes['data-object']
            assert 'mtime' in data_object
            assert 'time' in data_object['mtime']
            assert 'time-raw' in data_object['mtime']
            assert 'data' in data_object
            assert data == data_object['data']
