#!/usr/bin/env python

__author__ = 'jgarman'


from cbapi2 import CbApi2
import sys
import argparse
import Queue
import os
import threading
import json

import logging

worker_queue = Queue.Queue(maxsize=50)

def get_path_for_md5(d, basepath=''):
    d = d.upper()
    return os.path.join(basepath, d[:3], d[3:6], d)

def create_directory(pathname):
    try:
        os.makedirs(os.path.dirname(pathname))
    except:
        pass

class BinaryWorker(threading.Thread):
    def __init__(self, basepath):
        self.basepath = basepath
        threading.Thread.__init__(self)

    def already_exists(self, pathname, item):
        try:
            filesize = os.path.getsize(pathname)
            if filesize == item.copied_size:
                return True
        except:
            pass

        return False

    def run(self):
        l = logging.getLogger('co.redcanary.get_binaries.worker_thread')
        l.setLevel(logging.INFO)

        while True:
            item = worker_queue.get()
            pathname = get_path_for_md5(item.md5sum, self.basepath)

            if self.already_exists(pathname, item):
                l.info('already have %s' % item.md5sum)
            else:
                create_directory(pathname)
                write_progress = 0
                try:
                    open(pathname, 'wb').write(item.file.read())
                    write_progress += 1
                    json.dump(item.original_document, open(pathname + '.json', 'wb'))
                    write_progress += 1
                except:
                    pass

                if not write_progress:
                    l.error(u'Could not grab {0:s}'.format(item.md5sum))
                elif write_progress == 1:
                    l.info(u'Grabbed {0:s} binary'.format(item.md5sum))
                elif write_progress == 2:
                    l.info(u'Grabbed {0:s} binary & process document'.format(item.md5sum))
            worker_queue.task_done()


def dump_all_binaries(cb, destdir, start):
    threads = []
    num_worker_threads = 10
    for i in range(num_worker_threads):
        t = BinaryWorker(destdir)
        t.daemon = True
        t.start()
        threads.append(t)

    for binary in cb.binary_search(start=start):
        worker_queue.put(binary)

    worker_queue.join()


def main():
    parser = argparse.ArgumentParser(description="Grab all binaries from a Cb server")
    parser.add_argument('-d', '--destdir', action='store', help='Destination directory to place the events', default=os.curdir)

    parser.add_argument('--start', action='store', dest='startvalue', help='Start from result number', default=0)
    parser.add_argument('-v', action='store_true', dest='verbose', help='Enable verbose debugging messages',
                        default=False)
    parser.add_argument(action='store', nargs=1, dest='url', help='Cb server base URL', default='')
    parser.add_argument(action='store', nargs=1, dest='apikey', help='Cb server API key', default='')

    results = parser.parse_args()

    if results.verbose:
        l = logging.getLogger('co.redcanary')
        l.setLevel(logging.DEBUG)
    else:
        l = logging.getLogger('co.redcanary.get_binaries.worker_thread')
        l.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh = logging.FileHandler(os.path.join(results.destdir, 'log.txt'))
    fh.setFormatter(formatter)
    l.addHandler(ch)
    l.addHandler(fh)

    cb = CbApi2(results.url[0], results.apikey[0], ssl_verify=False)
    return dump_all_binaries(cb, results.destdir, int(results.startvalue))


if __name__ == '__main__':
    sys.exit(main())

