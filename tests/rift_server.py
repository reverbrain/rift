import subprocess
import time
import json
import os


class Server:
    def __init__(self, option, binary, port):
        config = {
            "endpoints": [
                "0.0.0.0:{0}".format(port)
            ],
            "backlog": 128,
            "threads": 2,
            "buffer_size": 65536,
            "logger": {
                "file": "/dev/stderr",
                "level": 4
            },
            "daemon": {
                "fork": False,
                "uid": 1000
            },
            #"monitor-port": 21000,
            "application": {
                "remotes": option.remotes,
                "groups": [
                    1, 2
                ],
                "metadata-groups": [
                    3, 4
                ],
                "read-timeout": 10,
                "write-timeout": 16,
                "XXX-redirect-port": 8080,
                "host": "localhost" # For s3 server only
            }
        }

        if option.bucket:
            config['application']['bucket'] = {
                "timeout": 60
            }

        self.config_path = os.path.join(option.temporary_path, "rift-config.json")
        json_config = json.dumps(config)
        with open(self.config_path, "w") as f:
            f.write(json_config)

        self.binary = binary
        if not self.binary:
            self.binary = "/usr/bin/rift_server"
        self.process = subprocess.Popen(args=[self.binary, "-c", self.config_path],
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE)

        time.sleep(2)

        assert self.process.poll() is None

    def stop(self):
        self.process.terminate()
        self.process.wait()
