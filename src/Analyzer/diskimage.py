import imagemounter
import os
import time
from . import files
import magic
import json
import yaml


class DiskImage():
    """This class represents a single disk image. The DiskImage has following attributes:

    Attributes:
        file: path to the disk image.
        mount_path: path to the mount location of the disk image.
        imagemounter_parser
        disks: parser.disks

    """
    
    def __init__(self):
        self.hash = {'sha1': '', 'md5': ''}
        self.disks = []
        self.files = []
        self.checked_size = ''
        self.volumes = {}
        self.path = None
        self.hex = None
        self.volume_info = {}
        self.magic = {'OEM_ID': '', 'root_entries': '', 'sectors_cluster': '',
                      'sectors_track': '', 'sectors_FAT': '', 'boot_sector': '',
                      'code_offset': '', 'serial_number': '', 'label': '',
                      'raw': ''}
        self.volume_info = {'description': '', 'formatted_size': '', 'fstype': '',
                            'size': '', 'block_size': '', 'sectors': '',
                            'info': {'blkid_data': {'LABEL': '', 'UUID': ''}}}

    def set_path(self, path):
        self.path = path

    def calculate_hash(self):
        self.hash['md5'] = files.get_hash(self.path, method='md5')
        self.hash['sha1'] = files.get_hash(self.path, method='sha1')

    def initialize(self):
        self.initialize_imagemounter()
        self.initialize_disks()

    def initialize_imagemounter(self, disk_mounter='xmount', vstype='dos', volume_detector='parted'):
        self.imagemounter_parser = imagemounter.ImageParser(paths=[self.path],
                                                            disk_mounter=disk_mounter,
                                                            # vstype=vstype,
                                                            # volume_detector=volume_detector)
                                                            )

    def to_dict(self):
        return {'disk': {'path': self.path,
                         'hash': self.hash,
                         'hex': str(self.hex),
                         'checked_size': self.checked_size,
                         'magic': self.magic,
                         'volume_info': self.volume_info},
                'files': self.files}

    def to_json(self):
        return json.dumps({'name': self.path, 'specification': {'disk': {'path': self.path,
                         'hash': self.hash,
                         'hex': str(self.hex),
                         'checked_size': self.checked_size,
                         'magic': self.magic,
                         'volume_info': self.volume_info},
                'files': self.files}}, ensure_ascii=True, indent=4)

    def to_yaml(self):
        return yaml.dump(self.to_dict())

    def magic_file_analyzing(self):
        m = magic.open(magic.MAGIC_NONE)
        m.load()
        magic_file = m.file(self.path)
        self.magic['raw'] = magic_file

        for i in magic_file.split(','):
            if 'OEM-ID' in i:
                i = i.replace(' OEM-ID ', '').replace('"', '')
                self.magic['OEM_ID'] = i
            elif 'root entries' in i:
                i = i.replace(' root entries ', '')
                self.magic['root_entries'] = i
            elif 'sectors/FAT' in i:
                i = i.replace(' sectors/FAT ', '')
                self.magic['sectors_FAT'] = i
            elif 'sectors/track' in i:
                i = i.replace(' sectors/track ', '')
                self.magic['sectors_track'] = i
            elif 'boot sector' in i:
                self.magic['boot_sector'] = str(i)
            elif 'sectors/cluster' in i:
                i = i.replace(' sectors/cluster ', '')
                self.magic['sectors_cluster'] = str(i)
            elif 'code offset' in i:
                i = i.replace(' code offset ', '')
                self.magic['code_offset'] = str(i)
            elif 'label:' in i:
                i = i.replace(' label: ', '').replace('"', '')
                self.magic['label'] = str(i)
            elif 'serial number' in i:
                i = i.replace(' serial number ', '')
                self.magic['serial_number'] = str(i)

    def initialize_disks(self):
        for disk in self.imagemounter_parser.disks:
            self.disks.append(disk)
            disk.init()
            disk.mount()

            volumes = disk.detect_volumes()
            for volume in volumes:
                self.get_all_files(volume)

    def get_mount_path(self):
        # TODO: is there always only one disk?
        return self.disks[0].mountpoint

    def check_size(self):
        ''' Check the file size against known disk sizes

        Possible sizes (WIP):

            Booter (160kB)
            Booter (180kB)
            5.25" DS SD (180kB)
            Booter (200kB)
            Booter (320kB)
            Booter (360kB)
            5.25" DS DD (360kB)
            Booter (400kB)
            3.5" DD (720kB)
            Booter (720kB)
            5.25" DS HD (1200kB)
            3.5" HD (1440kB)
        '''

        if self.volume_info['size'] == 163840:
            self.checked_size = 'Booter (160kB)'
        elif self.volume_info['size'] == 184320:
            self.checked_size = 'Booter (180kB) | 5.25" DS SD (180kB)'
        elif self.volume_info['size'] == 204800:
            self.checked_size = 'Booter (200kB)'
        elif self.volume_info['size'] == 327680:
            self.checked_size = 'Booter (320kB)'
        elif self.volume_info['size'] == 368640:
            self.checked_size = 'Booter (360kB) | 5.25" DS DD (360kB)'
        elif self.volume_info['size'] == 409600:
            self.checked_size = 'Booter (400kB)'
        elif self.volume_info['size'] == 737280:
            self.checked_size = 'Booter (720kB) | 3.5" DD (720kB)'
        elif self.volume_info['size'] == 1228800:
            self.checked_size = '5.25" DS HD (1200kB)'
        elif self.volume_info['size'] == 1474560:
            self.checked_size = '3.5" HD (1440kB)'
        else:
            self.checked_size = 'Wrong size'

        return self.checked_size

    def compare(self, disk):
        difference = {'disk': {}, 'files': {'same_name': {}, 'different_name': {'disk1': [], 'disk2': []}}}

        # check image
        if not self.hash['sha1'] == disk.hash['sha1'].upper():
            difference['disk']['hash'] = {'sha1': {'disk1': self.hash['sha1']}}
            difference['disk']['hash']['sha1']['disk2'] = disk.hash['sha1']

            difference['disk']['hash']['md5'] = {'disk1': self.hash['sha1']}
            difference['disk']['hash']['md5']['disk2'] = disk.hash['sha1']

        if not self.volume_info['info']['blkid_data']['LABEL'] == disk.volume_info['info']['blkid_data']['LABEL']:
            difference['disk']['LABEL'] = {'disk1': self.volume_info['info']['blkid_data']['LABEL']}
            difference['disk']['LABEL']['disk2'] = disk.volume_info['info']['blkid_data']['LABEL']

        if not self.volume_info['info']['blkid_data']['UUID'] == disk.volume_info['info']['blkid_data']['UUID']:
            difference['disk']['UUID'] = {'disk1': self.volume_info['info']['blkid_data']['UUID']}
            difference['disk']['UUID']['disk2'] = disk.volume_info['info']['blkid_data']['UUID']

        if not self.volume_info['size'] == disk.volume_info['size']:
            difference['disk']['size'] = {'disk1': self.volume_info['formatted_size'] + ' (' + str(self.volume_info['size']) + ')'}
            difference['disk']['size']['disk2'] = disk.volume_info['formatted_size'] + ' (' + str(disk.volume_info['size']) + ')'

        if not self.volume_info['block_size'] == disk.volume_info['block_size']:
            difference['disk']['block_size'] = {'disk1': self.volume_info['block_size']}
            difference['disk']['block_size']['disk2'] = disk.volume_info['block_size']

            difference['disk']['sectors'] = {'disk1': int(self.volume_info['size'] / self.volume_info['block_size'])}
            difference['disk']['sectors']['disk2'] = int(disk.volume_info['size'] / disk.volume_info['block_size'])

        if not self.volume_info['fstype'] == disk.volume_info['fstype']:
            difference['disk']['fstype'] = {'disk1': self.volume_info['fstype']}
            difference['disk']['fstype']['disk2'] = disk.volume_info['fstype']

        if not self.hex == disk.hex:
            difference['disk']['hex'] = {'disk1': self.hex}
            difference['disk']['hex']['disk2'] = disk.hex

        # check files
        disk_files_1 = {}
        disk_files_2 = {}

        for file in self.files:
            disk_files_1[file['name']] = file

        for file in disk.files:
            disk_files_2[file['name']] = file

        for filename in disk_files_1:
            if filename in disk_files_2:
                if not disk_files_1[filename] == disk_files_2[filename]:
                    difference['files']['same_name'][filename] = files.compare_files(disk_files_1[filename], disk_files_2[filename])
                del disk_files_2[filename]
            else:
                difference['files']['different_name']['disk1'].append(disk_files_1[filename])

        for filename in disk_files_2:
            difference['files']['different_name']['disk2'].append(disk_files_2[filename])

        return difference

    def unmount(self):
        self.imagemounter_parser.clean()

    def get_all_files(self, v):
        # for v in self.volumes[self.disks[0]]:
            v.init()
            v.mount()

            mountpoint = v.mountpoint
            file_i = 0
            for root, subdirs, f in os.walk(mountpoint):
                for file in f:
                    new_file = {'time': {}, 'hash': {}}

                    # set path
                    new_file['index'] = file_i

                    if root != mountpoint:
                        new_file['path'] = os.path.basename(root) + '/' + file
                    else:
                        new_file['path'] = file

                    # set name
                    new_file['name'] = new_file['path'].split('/')[-1]

                    # set attributes
                    # TODO: adjust path
                    new_file['attributes'] = files.get_fat_attrs(mountpoint + '/' + new_file['path'])

                    # set hash
                    new_file['hash']['md5'] = files.get_hash(mountpoint + '/' + new_file['path'], method='md5')
                    new_file['hash']['sha1'] = files.get_hash(mountpoint + '/' + new_file['path'], method='sha1')

                    file_info = os.stat(mountpoint + '/' + new_file['path'])
                    # set size
                    new_file['size'] = file_info.st_size

                    # set times
                    new_file['time']['mtime'] = time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime(file_info.st_mtime))
                    new_file['time']['ctime'] = time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime(file_info.st_ctime))
                    new_file['time']['atime'] = time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime(file_info.st_atime))

                    self.files.append(new_file)
                    file_i += 1

            v.determine_fs_type()
            self.volume_info['description'] = v.get_description()
            self.volume_info['formatted_size'] = v.get_formatted_size()
            self.volume_info['fstype'] = v.fstype
            self.volume_info['size'] = v.size
            self.volume_info['block_size'] = v.block_size
            self.volume_info['sectors'] = int(v.size / v.block_size)

            self.volume_info['info'] = v.info

            if 'blkid_data' not in self.volume_info['info']:
                self.volume_info['info'] = {'blkid_data': {'LABEL': '', 'UUID': ''}}
            if 'LABEL' not in self.volume_info['info']['blkid_data']:
                self.volume_info['info']['blkid_data']['LABEL'] = ''
            if 'UUID' not in self.volume_info['info']['blkid_data']:
                self.volume_info['info']['blkid_data']['UUID'] = ''

            v.unmount()
