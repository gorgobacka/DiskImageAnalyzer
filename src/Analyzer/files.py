import os
import array
import fcntl
import hashlib

FAT_IOCTL_GET_ATTRIBUTES = 0x80047210
FATATTR_BITS = 'rhsvda67'


def get_hash(path_to_file, method='sha1'):
    BLOCKSIZE = 65536
    if method == 'sha1':
        hasher = hashlib.sha1()
    elif method == 'md5':
        hasher = hashlib.md5()
    else:
        # TODO: error message
        return None
    with open(path_to_file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()


def get_fat_attrs(fn):
    fd = os.open(fn, os.O_RDONLY)
    try:
        buf = array.array('L', [0])
        try:
            fcntl.ioctl(fd, FAT_IOCTL_GET_ATTRIBUTES, buf, True)
        except IOError as ioe:
            if ioe.errno == 25:  # Not a FAT volume
                return None
            else:
                raise
        s = ''.join((fb if (1 << idx) & buf[0] else ' ')
                    for idx, fb in enumerate(FATATTR_BITS))
        return s
    finally:
        os.close(fd)


def compare_files(files1, files2):
    difference = {'time': {'atime': {}, 'mtime': {}, 'ctime': {}},
                  'path': {}, 'size': {}, 'name': {}, 'hash': {'sha1': {}, 'md5': {}},
                  'index': {}, 'attributes': {}}

    if not files1['time']['atime'] == files2['time']['atime']:
        difference['time']['atime']['disk1'] = files1['time']['atime']
        difference['time']['atime']['disk2'] = files2['time']['atime']

    if not files1['time']['mtime'] == files2['time']['mtime']:
        difference['time']['mtime']['disk1'] = files1['time']['mtime']
        difference['time']['mtime']['disk2'] = files2['time']['mtime']

    if not files1['time']['ctime'] == files2['time']['ctime']:
        difference['time']['ctime']['disk1'] = files1['time']['ctime']
        difference['time']['ctime']['disk2'] = files2['time']['ctime']

    if not files1['path'] == files2['path']:
        difference['path']['disk1'] = files1['path']
        difference['path']['disk2'] = files2['path']

    if not files1['size'] == files2['size']:
        difference['size']['disk1'] = files1['size']
        difference['size']['disk2'] = files2['size']

    if not files1['name'] == files2['name']:
        difference['name']['disk1'] = files1['name']
        difference['name']['disk2'] = files2['name']

    if not files1['index'] == files2['index']:
        difference['index']['disk1'] = files1['index']
        difference['index']['disk2'] = files2['index']

    if not files1['attributes'] == files2['attributes']:
        difference['attributes']['disk1'] = files1['attributes']
        difference['attributes']['disk2'] = files2['attributes']

    if not files1['hash']['sha1'] == files2['hash']['sha1']:
        difference['hash']['sha1']['disk1'] = files1['hash']['sha1']
        difference['hash']['sha1']['disk2'] = files2['hash']['sha1']

    if not files1['hash']['md5'] == files2['hash']['md5']:
        difference['hash']['md5']['disk1'] = files1['hash']['md5']
        difference['hash']['md5']['disk2'] = files2['hash']['md5']

    return difference
