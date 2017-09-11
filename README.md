# DiskImageAnalyzer

DiskImageAnalyzer is a Python 3 tool for analyzing floppy disk images on Linux.

## Installation

### Required dependencies

- Python 3
- [imagemounter](https://github.com/ralphje/imagemounter), for mounting the images
- [PyYAML](https://pypi.python.org/pypi/PyYAML)
- [filemagic](https://pypi.python.org/pypi/filemagic), for using the Unix file command

## Usage

Basic introduction:

   `./analyzer.py -h`

DiskImageAnalyzer has two main functions:
- print an extensive set of information about a disk image file
- compare two disk image files

It is important to run this tool as sudo. Otherwise the disk images can't be mounted and therefore not analyzed completely.

Analyze a single disk image:

   `sudo ./analyzer.py disk.img`
   
Compare two disk images:

   `sudo ./analyzer.py disk1.img --compare disk2.img`
   
## License

Licensed under the [GNU GPLv3 license](http://www.gnu.org/licenses/gpl-3.0).