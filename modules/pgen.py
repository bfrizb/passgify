#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author:        Brian Frisbie <bfrizb on GitHub>
#
# To create a new OSX sparsebundle:
# - From existing folder: hdiutil create "{}.dmg" -encryption -srcfolder "{}" -volname "{}"
# - New Sparsebundle: Use create_encrypted_sparsebundle.sh
import argparse
import getpass
import hashlib
import logging
import os
import pkg_resources
import pyperclip
import random
import subprocess
import sys
import time
import yaml

PROGRAM_NAME = 'passgify'
PROGRAM_PURPOSE = """Generates passwords from a hashed service_id's, salt, and secret key"""
DEFAULT_CONFIG_FILE = '{0}/.pgen.yaml'.format(os.path.expanduser('~'))
SPECIAL_CHARS = [chr(x) for x in range(33, 48) + range(58, 65) + range(91, 97)]
DEFAULT_PB64_MAP = [chr(x) for x in range(65, 73) + range(74, 79) + range(80, 91)] + \
                   [chr(x) for x in range(97, 108) + range(109, 123)] + \
                   [str(x) for x in range(0, 10)] + [str(x) for x in range(0, 5)]
# ^ "I", "l", & "O" are excluded


class PGen(object):

    def generate_password(self, service_id, prefix, length, config_path, decrypt_disk_image_path):
        """Generate the password based on supplied parameters.

        Args:
            service_id (string): service id used to generate the password from a hashing algorithm
            prefix (string): prefix of generated password
            length (positive int): length of generated password
            config_path (string): yaml configuration file path
            decrypt_disk_image_path (boolean): indicates whether to decrypt a disk image
        """
        self.read_config(config_path)

        # Get default prefix if None is set
        if prefix is None:
            prefix = self.default_prefix

        # Get default length if None is set
        len_error = ValueError('Length must be a positive integer. "{0}" was provided for the length (either via the '
                               'command line or in the config file, "{1}"'.format(length, config_path))
        if length is None:
            try:
                length = int(self.default_length)
            except ValueError:
                raise len_error
        else:
            try:
                length = int(length)
            except ValueError:
                raise len_error
        if length < 1:
            raise len_error

        # Get the hashing algorithm
        try:
            hash_method = getattr(hashlib, self.algorithm)
        except AttributeError:
            config_path = DEFAULT_CONFIG_FILE if (config_path is None) else config_path
            raise AttributeError(
                '"{0}" is not a hashing algorithm supported by hashlib. Please edit or delete the '
                'configuration file located here: {1}. Here is the list of supported algorithms: {2}'.format(
                    self.algorithm, config_path, repr(hashlib.algorithms)))

        # Get number of seconds to wait until overwriting the password in the clipboard
        overwrite_error = ValueError(
            'Seconds to wait until overwriting the password must be a positive integer. "{0}" was provided for this '
            'value in the config file, "{1}"'.format(self.sec_til_overwrite, config_path))
        try:
            sec_til_overwrite = int(self.sec_til_overwrite)
        except ValueError:
            raise overwrite_error
        if sec_til_overwrite <= 0:
            raise overwrite_error

        # Get Secret Key
        sys.stdout.write('Secret Key: ')
        secret_key = getpass.getpass(prompt='')

        # Generate the "full length" password
        pb64_hash = pb64_digest(hash_method(service_id + self.salt + secret_key).hexdigest())
        full_password = prefix + pb64_hash

        # Check that requested password length isn't too long
        if len(full_password) < length:
            raise ValueError('The max password length for your chosen prefix is {0} characters'.format(
                len(full_password)))

        # Check if the user wants to decrypt a disk image
        if decrypt_disk_image_path is not None:
            decrypt_image(decrypt_disk_image_path, full_password[:length])
        else:
            pyperclip.copy(full_password[:length])
            overwrite_countdown(length, sec_til_overwrite)

    def read_config(self, config_path):
        """ Reads the configuration file for the salt, default password length, and default password prefix

        Args:
            config_path (string): yaml configuration file path
        """
        try:
            with open(config_path, 'r') as fh:
                yaml_content = yaml.load(fh)
        except IOError:
            fh = create_config_file(config_path)
            yaml_content = yaml.load(fh)
            fh.close()

        # Read contents of file
        try:
            self.default_length = yaml_content['default_length']
            self.default_prefix = yaml_content['default_prefix']
            self.salt = yaml_content['salt']
            self.algorithm = yaml_content['hashing_algorithm']
            self.sec_til_overwrite = yaml_content['seconds_until_overwrite']
            self.pb64_map = yaml_content['pseudo_base64_map']
        except KeyError:
            raise KeyError('The file "{0}" does not contain entries for one or more of the following required '
                           'values in the YAML format: "salt", "default_prefix", "default_length", '
                           '"hashing_algorithm", or "seconds_until_overwrite"'.format(config_path))


def create_config_file(config_path):
    """Creates a yaml configuration file. This method is invoked if the default config file does not exist.

    Args:
        config_path (string): yaml configuration file path
    Returns:
        A file handle (read-only) to the newly created config file, None on error
    """
    logging.info('No configuration file found. Creating a config file.')
    # Choose config file path, default length, default prefix, and salt
    file_path = raw_input('Choose config File PATH [{0}]: '.format(config_path))
    if len(file_path.strip()) == 0:
        file_path = config_path
    default_length = raw_input('Choose default Password LENGTH [32]: ')
    if len(default_length.strip()) == 0:
        default_length = 32
    rand_prefix = random.sample(SPECIAL_CHARS, 1)[0] + random.sample(SPECIAL_CHARS, 1)[0]
    default_prefix = raw_input('Choose default Password PREFIX [{0}]: '.format(rand_prefix))
    if len(default_prefix.strip()) == 0:
        default_prefix = rand_prefix
    rand_salt = pb64_digest(hashlib.sha512(str(random.random())).hexdigest())[:4]
    salt = raw_input('Choose password SALT [{0}]: '.format(rand_salt))
    if len(salt.strip()) == 0:
        salt = rand_salt
    sec_til_overwrite = raw_input('Choose the default number of seconds to wait before overwriting the generated '
                                  'password stored in the clipboard [10]: ')
    if len(sec_til_overwrite.strip()) == 0:
        sec_til_overwrite = 10

    # Choose hashing algorithm
    algorithm = None
    while algorithm not in hashlib.algorithms:
        if algorithm is not None:
            raise AttributeError(
                '"{0}" is not a hashing algorithm supported by hashlib. Here is the list of '
                'supported algorithms: {1}'.format(algorithm, repr(hashlib.algorithms)))
        algorithm = raw_input('Choose a hashing algorithm [sha512]: ')
        if len(algorithm.strip()) == 0:
            algorithm = 'sha512'

    # Write chosen options to the config YAML file
    try:
        with open(file_path, 'w') as fh:
            fh.write(
                yaml.dump({
                    'default_length': default_length, 'default_prefix': default_prefix, 'salt': salt,
                    'hashing_algorithm': algorithm, 'seconds_until_overwrite': sec_til_overwrite,
                    'pseudo_base64_map': DEFAULT_PB64_MAP,
                }, default_flow_style=False))
    except IOError:
        raise IOError('Cannot open the file "{0}" for writing. Perhaps there is a permission error on the file '
                      'or the parent directory?'.format(file_path))

    return open(config_path, 'r')


def pb64_digest(hex_digest):
    """Pseudo-Base64 Digest

    Alphabet = a-zA-Z0-9 (excluding I, l, & O). The digits 0-4 are twice as likely to occur in order to get
    to a mapping to 64 (non-unique) characters.

    Args:
        hex_digest (string): A hex_digest generated from a hashing algorithm
    Returns:
        A pseudo-base64 digest
    """
    pb_digest = ''
    for i in range(3, len(hex_digest) + 1, 3):
        twelve_bits = int(hex_digest[i - 3:i], 16)
        bits1 = twelve_bits & 0x3f      # hex(63) == 0x3f
        bits2 = twelve_bits >> 6        # 2^6 = 64
        """ Alternative pb64 algorithm
        bits1 = (twelve_bits >> 6) & 0x3f      # hex(63) == 0x3f
        bits2 = twelve_bits & 0x3f             # hex(63) == 0x3f
        """
        pb_digest += DEFAULT_PB64_MAP[bits1] + DEFAULT_PB64_MAP[bits2]
    return pb_digest


def decrypt_image(decrypt_disk_image_path, password):
    """Decrypts a disk image using the generated password instead of copying it to the clipboard

    Args:
        decrypt_disk_image_path: the path of the disk image to decrypt
        password: the password to use to decrypt the disk image
    """

    if sys.platform != 'darwin':
        raise SystemError('The "decrypt_disk_image_path" option currently only works on the Darwin platform '
                          '(e.g. Mac OS X). You are running on the "{0}" platform'.format(sys.platform))
    p = subprocess.Popen(['hdiutil', 'attach', decrypt_disk_image_path, '-stdinpass'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    p.stdin.write(password)
    (output, error) = p.communicate()

    if len(error) > 0:
        logging.error('hdiutil Error Message --> {0}\n'.format(error))
    if len(output) > 0:
        logging.info('hdiutil Output --> {0}\n'.format(output))


def overwrite_countdown(password_length, countdown_seconds=10):
    """Prints a countdown timer to stdout once each second, then writes 'z' characters to the clipboard

    Args:
        password_length (positive int): the length of the generated password
        countdown_seconds (positive int): number of seconds in the countdown, until the clipboard overwrite occurs
    """
    if not int(password_length) or password_length < 0:
        raise ValueError('Password Length must be a positive integer. password_length = {0}'.format(password_length))
    while countdown_seconds > 0:
        sys.stdout.write('Overwriting clipboard in...{0}\r'.format(countdown_seconds))
        sys.stdout.flush()
        time.sleep(1)
        countdown_seconds -= 1
    sys.stdout.write('Overwriting clipboard in...0\r')
    sys.stdout.write('\n')

    pyperclip.copy('z' * 2 * password_length)


def main(args):
    logging.basicConfig(level=logging.INFO)
    pgen = PGen()
    pgen.generate_password(args.service_id, args.prefix, args.length, args.config_path, args.decrypt_disk_image_path)


def parse_args():
    try:
        version = pkg_resources.require(PROGRAM_NAME)[0].version
    except pkg_resources.DistributionNotFound:
        version = '(Install with "sudo python setup.py install" to get program version number)'

    parser = argparse.ArgumentParser(prog=PROGRAM_NAME, description=PROGRAM_PURPOSE)
    parser.add_argument('-v', '--version', action='version', version='{0} {1}'.format(
        PROGRAM_NAME, version))
    parser.add_argument('service_id', help='[REQUIRED] A service identifier. It can be anything really, as long as '
                        'its unique. A common choice is the name of the service, such as a website name (e.g. google, '
                        'amazon)')
    parser.add_argument('-c', '--config_path', default=DEFAULT_CONFIG_FILE, help='[OPTIONAL] Path to the YAML '
                        'configuration file for this program (default = "%(default)s")')
    parser.add_argument('-l', '--length', type=int, help='[OPTIONAL] Length of hashed password including its prefix')
    parser.add_argument('-p', '--prefix', help='[OPTIONAL] Prefix to hashed password')
    parser.add_argument('-d', '--decrypt_disk_image_path', default=None, metavar='IMAGE_PATH', help='[OPTIONAL] '
                        'Instead of copying the generated password to the clipboard, use it to open a disk image '
                        'located at PATH (Only supported for disk images on Mac OS X currently.')
    return parser.parse_args()

if __name__ == '__main__':
    main(parse_args())
