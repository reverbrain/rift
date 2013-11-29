#!/usr/bin/python
# -*- coding: utf-8 -*-

import elliptics
import msgpack

class Options(object):
    def __init__(self):
        self.bucket_groups = None
        self.metadata_groups = None
        self.remotes = None
        self.log_file = None
        self.log_level = None
        self.bucket = None
	self.token = None
	self.noauth = None

def parse_options():
    from optparse import OptionParser

    options = Options()

    parser = OptionParser()
    parser.usage = "%prog type [options]"
    parser.description = __doc__
    parser.add_option("-b", "--bucket", dest="bucket", default=None, help="Bucket name [default: %default]")
    parser.add_option("-t", "--token", dest="token", default=None, help="Authentication token [default: %default]")
    parser.add_option("-n", "--noauth", dest="noauth", default=None,
	    help="When provided bucket IO will not check authentication [default: %default], possible values: 'read' - allow read operation with auth, 'all' - do not perform authentication for given bucket")
    parser.add_option("-g", "--bucket-groups", action="store", dest="bucket_groups", default=None,
                      help="Comma separated list of groups where data for given bucket has to be stored")
    parser.add_option("-m", "--metadata-groups", action="store", dest="metadata_groups", default=None,
                      help="Comma separated list of groups where bucket metadata is stored")
    parser.add_option("-l", "--log", dest="log_file", default='/dev/stderr', metavar="FILE",
                      help="Output log messages from library to file [default: %default]")
    parser.add_option("-L", "--log-level", action="store", dest="log_level", default="1",
                      help="Elliptics client verbosity [default: %default]")
    parser.add_option("-r", "--remote", action="append", dest="remote",
                      help="Elliptics node address [default: %default]")

    (parsed_options, args) = parser.parse_args()

    if not parsed_options.bucket_groups or not parsed_options.metadata_groups:
        raise ValueError("Please specify all groups options")

    if not parsed_options.bucket:
        raise ValueError("Please specify bucket")

    def parse_groups(string):
        try:
            return map(int, string.split(','))
        except Exception as e:
            raise ValueError("Can't parse groups list: '{0}': {1}".format(parsed_options.groups, repr(e)))

    options.metadata_groups = parse_groups(parsed_options.metadata_groups)
    print("Using metadata groups list: {0}".format(options.metadata_groups))

    options.bucket_groups = parse_groups(parsed_options.bucket_groups)
    print("Using bucket data groups list: {0}".format(options.bucket_groups))

    try:
        options.log_file = parsed_options.log_file
        options.log_level = int(parsed_options.log_level)
    except Exception as e:
        raise ValueError("Can't parse log_level: '{0}': {1}".format(parsed_options.log_level, repr(e)))

    print("Using elliptics client log level: {0}".format(options.log_level))

    if not parsed_options.remote:
        raise ValueError("Please specify at least one remote address (-r option)")
    try:
        options.remotes = []
        for r in parsed_options.remote:
            options.remotes.append(elliptics.Address.from_host_port_family(r))
            print("Using remote host:port:family: {0}".format(options.remotes[-1]))
    except Exception as e:
        raise ValueError("Can't parse host:port:family: '{0}': {1}".format(parsed_options.remote, repr(e)))

    options.bucket = parsed_options.bucket
    options.token = parsed_options.token
    options.noauth = parsed_options.noauth

    return options

if __name__ == '__main__':
    options = parse_options()

    logger = elliptics.Logger(options.log_file, options.log_level)
    node = elliptics.Node(logger)

    any_remote = False

    for remote in options.remotes:
        try:
            node.add_remote(remote)
            any_remote = True
        except Exception as e:
            print("Couldn't connect to remote: {0} got: {1}".format(remote, e))

    if not any_remote:
        raise ValueError("Couldn't connect to any remote")

    sess = elliptics.Session(node)
    sess.groups = options.metadata_groups

    flags = 0
    if options.noauth == "read":
	    flags = 1
    elif options.noauth == "all":
	    flags = 2

    bucket = [ 1, options.bucket, options.token, options.bucket_groups, flags ]
    data = msgpack.packb(bucket)

    write_result = sess.write_data(options.bucket, data)
    write_result.wait()
