#!/usr/bin/python3

from Analyzer import diskimage
from operator import itemgetter
import binascii
import os
import argparse


def analyze_disc(image_file):
    with open(image_file, 'rb') as f:
            hexdata = binascii.hexlify(f.read())
            hexdata_top = binascii.unhexlify(hexdata[0:200])

    disk = diskimage.DiskImage()
    disk.set_path(image_file)
    disk.hex = hexdata_top
    disk.magic_file_analyzing()
    disk.volume_info['size'] = os.stat(image_file).st_size
    disk.check_size()

    disk.calculate_hash()

    try:
            disk.initialize()
            files = disk.files
            disk.unmount()
    except:
            pass

    return disk, files


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze floppy disk images. This programm needs to be run with sudo for mounting the image files.')
    parser.add_argument('path', metavar='PATH', type=str,
                        help='Path to the disk image')
    parser.add_argument('--output', metavar='FORMAT', type=str, default='yaml',
                        help='Output format (default: yaml)')
    parser.add_argument('--compare', metavar='PATH', type=str, default='',
                        help='Path to the second disk image')
    args = parser.parse_args()

    disk, files = analyze_disc(args.path)

    if not args.compare:
        if args.output == 'text':
            print('### Disk image ###')
            print()
            print('Image file:\t\t' + disk.path)
            print()
            print('SHA1:\t\t\t' + disk.hash['sha1'])
            print('Size:\t\t\t' + disk.volume_info['formatted_size'] + ' (' + str(disk.volume_info['size']) + ')')
            print('Checked Size:\t\t' + disk.check_size())
            print('Boot sector:\t\t' + disk.magic['boot_sector'])
            print('File System:\t\t' + str(disk.volume_info['fstype']).upper())
            print()
            print('Volume Label:\t\t' + disk.volume_info['info']['blkid_data']['LABEL'] + ' (' + disk.magic['label'] + ')')
            print('OEM-ID:\t\t\t' + disk.magic['OEM_ID'])
            print('Serial number:\t\t' + disk.volume_info['info']['blkid_data']['UUID'])
            print()
            print('Root entries:\t\t' + disk.magic['root_entries'])
            print('Sectors:\t\t' + str(disk.volume_info['sectors']))
            print('Sectors per Cluster:\t' + disk.magic['sectors_cluster'])
            print('Sectors per Track:\t' + disk.magic['sectors_track'])
            print('Sectors per FAT:\t' + disk.magic['sectors_FAT'])
            print('Bytes per Sector:\t' + str(disk.volume_info['block_size']))

            print()
            print('### Content ###')
            print()

            for file in sorted(files, key=itemgetter('index')):
                print(file['path'] + '\t' + str(file['size']) + '\t' + file['attributes'] + '\t' + file['hash']['sha1'] + '\t' + file['time']['mtime'] + '\t' + file['time']['ctime'] + '\t' + file['time']['atime'])
                # print(file.path)
                # print('\tSize: ' + str(file.size))
                # print('\tAttributes: ' + file.attributes)
                # print('\tSHA1: ' + file.hash['sha1'])
                # print('\tTime modified: ' + file.time['mtime'])
                # print('\tTime created: ' + file.time['ctime'])
                # print('\tTime most recent access: ' + file.time['atime'])

        elif args.output == 'yaml':
            print(disk.to_yaml())
        elif args.output == 'json':
            print(disk.to_json())

    else:
        compare_disk, compare_files = analyze_disc(args.compare)

        difference = disk.compare(compare_disk)

        print()
        print('############################################################################')
        print()
        print('### Disk image ###')
        print()

        if 'hex' in difference['disk']:
            print('Hex Disk1:')
            print(difference['disk']['hex']['disk1'])
            print()
            print('Hex Disk2:')
            print(difference['disk']['hex']['disk2'])
            print()

        if 'hash' in difference['disk']:
            print('SHA1 Disk1: ' + difference['disk']['hash']['sha1']['disk1'])
            print('SHA1 Disk2: ' + difference['disk']['hash']['sha1']['disk2'])

        if 'LABEL' in difference['disk']:
            print('Volume Label Disk1: ' + difference['disk']['LABEL']['disk1'])
            print('Volume Label Disk2: ' + difference['disk']['LABEL']['disk2'])

        if 'UUID' in difference['disk']:
            print('Serial number Disk1: ' + difference['disk']['UUID']['disk1'])
            print('Serial number Disk2: ' + difference['disk']['UUID']['disk2'])

        if 'size' in difference['disk']:
            print('Size Disk1: ' + difference['disk']['size']['disk1'])
            print('Size Disk2: ' + difference['disk']['size']['disk2'])

        if 'block_size' in difference['disk']:
            print('Bytes per Sector Disk1: ' + difference['disk']['block_size']['disk1'])
            print('Bytes per Sector Disk2: ' + difference['disk']['block_size']['disk2'])

        if 'sectors' in difference['disk']:
            print('Sectors Disk1: ' + difference['disk']['sectors']['disk1'])
            print('Sectors Disk2: ' + difference['disk']['sectors']['disk2'])

        if 'fstype' in difference['disk']:
            print('File System Disk1: ' + difference['disk']['fstype']['disk1'])
            print('File System Disk2: ' + difference['disk']['fstype']['disk2'])

        print()
        print('### Content ###')
        print()
        print('# Same filenames #')
        print()
        for file in difference['files']['same_name']:
            if not difference['files']['same_name'][file] == {'time': {'atime': {}, 'mtime': {}, 'ctime': {}},
                  'path': {}, 'size': {}, 'name': {}, 'hash': {'sha1': {}, 'md5': {}},
                  'index': {}, 'attributes': {}}:
                print(file)
                print()
                if difference['files']['same_name'][file]['time']['atime']:
                    print('\tTime most recent access Disk1: ' + difference['files']['same_name'][file]['time']['atime']['disk1'])
                    print('\tTime most recent access Disk2: ' + difference['files']['same_name'][file]['time']['atime']['disk2'])
                    print()
                if difference['files']['same_name'][file]['time']['ctime']:
                    print('\tTime created Disk1: ' + difference['files']['same_name'][file]['time']['ctime']['disk1'])
                    print('\tTime created Disk2: ' + difference['files']['same_name'][file]['time']['ctime']['disk2'])
                    print()
                if difference['files']['same_name'][file]['time']['mtime']:
                    print('\tTime modified Disk1: ' + difference['files']['same_name'][file]['time']['mtime']['disk1'])
                    print('\tTime modified Disk2: ' + difference['files']['same_name'][file]['time']['mtime']['disk2'])
                    print()
                if difference['files']['same_name'][file]['hash']['sha1']:
                    print('\tSHA1 Disk1: ' + difference['files']['same_name'][file]['hash']['sha1']['disk1'])
                    print('\tSHA1 Disk2: ' + difference['files']['same_name'][file]['hash']['sha1']['disk2'])
                    print()
                if difference['files']['same_name'][file]['path']:
                    print('\tPath Disk1: ' + difference['files']['same_name'][file]['path']['disk1'])
                    print('\tPath Disk2: ' + difference['files']['same_name'][file]['path']['disk2'])
                    print()
                if difference['files']['same_name'][file]['name']:
                    print('\tName Disk1: ' + difference['files']['same_name'][file]['name']['disk1'])
                    print('\tName Disk2: ' + difference['files']['same_name'][file]['name']['disk2'])
                    print()
                if difference['files']['same_name'][file]['size']:
                    print('\tSize Disk1: ' + str(difference['files']['same_name'][file]['size']['disk1']))
                    print('\tSize Disk2: ' + str(difference['files']['same_name'][file]['size']['disk2']))
                    print()
                if difference['files']['same_name'][file]['index']:
                    print('\tIndex Disk1: ' + str(difference['files']['same_name'][file]['index']['disk1']))
                    print('\tIndex Disk2: ' + str(difference['files']['same_name'][file]['index']['disk2']))
                    print()
                if difference['files']['same_name'][file]['attributes']:
                    print('\tAttributes Disk1: ' + difference['files']['same_name'][file]['attributes']['disk1'])
                    print('\tAttributes Disk2: ' + difference['files']['same_name'][file]['attributes']['disk2'])
                    print()
            else:
                print(file + '\t is identical')

        print()
        print('# Different filenames #')
        print()
        print('Disk1:')
        print()
        for file in difference['files']['different_name']['disk1']:
            print(file['path'])

        print()
        print('Disk2:')
        print()
        for file in difference['files']['different_name']['disk2']:
            print(file['path'])

            # print(json.dumps(difference, indent=2))
