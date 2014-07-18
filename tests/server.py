import subprocess
import os
import shutil
import json


class Server:
    def __init__(self, groups):
        self.path = "temp"

        if os.path.exists(self.path):
            shutil.rmtree(self.path)
        os.mkdir(self.path)

        config = {
            'path': self.path,
            'srw': False,
            'servers': [
                {
                    'group': group,
		            'indexes_shard_count': 1
                } for group in groups
            ]
        }

        self.log = open(os.path.join(self.path, "server.log"), "w")

        self.process = subprocess.Popen(args=["dnet_run_servers"],
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=self.log)

        js = json.dumps(config)
        self.process.stdin.write(js + '\0')

        assert self.process.poll() is None

        while self.process.poll() is None:
            js = self.process.stdout.readline()
            if js:
                self.config = json.loads(js)
                break

        assert self.process.poll() is None

        self.remotes = [str(x['remote']) for x in self.config['servers']]

    def stop(self):
        self.process.terminate()
        self.process.wait()
        self.log.close()
