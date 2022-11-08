#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Author:        Brian Frisbie <bfrizb on GitHub>
#
# To create a new macOS sparsebundle:
# - From existing folder: hdiutil create "{}.dmg" -encryption -srcfolder "{}" -volname "{}"
# - New Sparsebundle: Use create_encrypted_sparsebundle.sh
import argparse
import getpass
import hashlib
import logging
import os
import random
import subprocess
import sys
import time
from itertools import chain

import pkg_resources
import pyperclip
import yaml

# Constants
PROGRAM_NAME = "passgify"
PROGRAM_PURPOSE = (
    "Generates a password from a hashed service_id, a salt, and a secret key"
)
DEFAULT_VERSION = 3
DEFAULT_CONFIG_FILE = os.path.join(
    os.path.expanduser("~"), ".{}.yaml".format(PROGRAM_NAME)
)
SPECIAL_CHARS = [chr(x) for x in chain(range(33, 48), range(58, 65), range(91, 97))]
DEFAULT_PB64_MAP = (
    [chr(x) for x in chain(range(65, 73), range(74, 79), range(80, 91))]
    + [chr(x) for x in chain(range(97, 108), range(109, 123))]
    + [str(x) for x in range(0, 10)]
    + [str(x) for x in range(0, 5)]
)
# ^ "I", "l", & "O" are intentionally excluded from DEFAULT_PB64_MAP


def pb64_digest(hex_digest, pb64_map, alg_version):
    """Returns the Pseudo-Base64 Digest.

    Alphabet = a-zA-Z0-9 (excluding I, l, & O). The digits 0-4 are twice as likely to occur in order to get
    to a mapping to 64 (non-unique) characters.

    Args:
        hex_digest (string): A hex_digest generated from a hashing algorithm
        alg_version (int): The version of the passgify algorithm to use
    Returns:
        A pseudo-base64 digest
    """
    pb_digest = ""
    for i in range(3, len(hex_digest) + 1, 3):
        twelve_bits = int(hex_digest[i - 3 : i], 16)
        if alg_version >= 3:
            bits1 = (twelve_bits >> 6) & 0x3F  # hex(63) == 0x3f
            bits2 = twelve_bits & 0x3F  # hex(63) == 0x3f
        elif alg_version == 2:
            bits1 = twelve_bits & 0x3F  # hex(63) == 0x3f
            bits2 = twelve_bits >> 6  # 2^6 = 64
        pb_digest += pb64_map[bits1] + pb64_map[bits2]
    return pb_digest


def create_config_file(config_path):
    """Creates a yaml configuration file. This method is invoked if the default config file does not exist.

    Args:
        config_path (string): yaml configuration file path
    Returns:
        A file handle (read-only) to the newly created config file, None on error
    """
    logging.info("No configuration file found. Creating a config file.")

    # Choose config file path, default length, default prefix, and salt
    file_path = input("Choose config File PATH [{0}]: ".format(config_path))
    if len(file_path.strip()) == 0:
        file_path = config_path
    default_length = input("Choose default Password LENGTH [32]: ")
    if len(default_length.strip()) == 0:
        default_length = 32
    rand_prefix = (
        random.sample(SPECIAL_CHARS, 1)[0] + random.sample(SPECIAL_CHARS, 1)[0]
    )
    default_prefix = input("Choose default Password PREFIX [{0}]: ".format(rand_prefix))
    if len(default_prefix.strip()) == 0:
        default_prefix = rand_prefix
    rand_salt = pb64_digest(
        hashlib.sha512(str(random.random()).encode("utf-8")).hexdigest(),
        DEFAULT_PB64_MAP,
        DEFAULT_VERSION,
    )[:4]
    salt = input("Choose password SALT [{0}]: ".format(rand_salt))
    if len(salt.strip()) == 0:
        salt = rand_salt
    seconds_until_overwrite = input(
        "Choose the default number of seconds to wait before overwriting the generated "
        "password stored in the clipboard [10]: "
    )
    if len(seconds_until_overwrite.strip()) == 0:
        seconds_until_overwrite = 10

    # Choose hashing algorithm
    hash_alg = None
    while hash_alg not in hashlib.algorithms_available:
        if hash_alg is not None:
            raise AttributeError(
                '"{0}" is not a hashing algorithm supported by hashlib. Here is the list of '
                "supported algorithms: {1}".format(
                    hash_alg, repr(hashlib.algorithms_available)
                )
            )
        hash_alg = input("Choose a hashing algorithm [sha512]: ")
        if len(hash_alg.strip()) == 0:
            hash_alg = "sha512"

    # Write chosen options to the config YAML file
    try:
        with open(file_path, "w") as fh:
            fh.write(
                yaml.dump(
                    {
                        "default_algorithm_version": DEFAULT_VERSION,
                        "default_length": default_length,
                        "default_prefix": default_prefix,
                        "salt": salt,
                        "hashing_algorithm": hash_alg,
                        "seconds_until_overwrite": seconds_until_overwrite,
                        "pseudo_base64_map": DEFAULT_PB64_MAP,
                    },
                    default_flow_style=False,
                )
            )
    except IOError:
        raise IOError(
            'Cannot open the file "{0}" for writing. Perhaps there is a permission error on the file '
            "or the parent directory?".format(file_path)
        )

    return open(config_path, "r")


def read_config(config_path):
    """Reads the configuration file for the salt, default password length, and default password prefix

    Args:
        config_path (string): yaml configuration file path
    """
    try:
        with open(config_path, "r") as fh:
            yaml_content = yaml.safe_load(fh)
    except IOError:
        fh = create_config_file(config_path)
        yaml_content = yaml.safe_load(fh)
        fh.close()
    return yaml_content


def decrypt_image(decrypt_disk_image_path, password):
    """Decrypts a disk image using the generated password instead of copying it to the clipboard.

    Args:
        decrypt_disk_image_path: the path of the disk image to decrypt
        password: the password to use to decrypt the disk image
    """

    if sys.platform != "darwin":
        raise NotImplementedError(
            'The "decrypt_disk_image_path" option currently only works on the Darwin platform '
            '(e.g. Mac OS X). You are running on the "{0}" platform'.format(
                sys.platform
            )
        )
    p = subprocess.Popen(
        ["hdiutil", "attach", decrypt_disk_image_path, "-stdinpass"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
    )
    p.stdin.write(password.encode())
    (output, error) = p.communicate()

    if len(error) > 0:
        logging.error("hdiutil Error Message --> {0}\n".format(error))
    if len(output) > 0:
        logging.info("hdiutil Output --> {0}\n".format(output))


def overwrite_password(password_length, countdown_seconds=10):
    """Prints a countdown timer to stdout once each second, then writes 'z' characters to the clipboard.

    Args:
        password_length (positive int): the length of the generated password
        countdown_seconds (positive int): number of seconds in the countdown, until the clipboard overwrite occurs
    """
    if not int(password_length) or password_length < 0:
        raise ValueError(
            "Password Length must be a positive integer. password_length = {0}".format(
                password_length
            )
        )
    while countdown_seconds > 0:
        sys.stdout.write("Overwriting clipboard in...{0} \r".format(countdown_seconds))
        sys.stdout.flush()
        time.sleep(1)
        countdown_seconds -= 1
    sys.stdout.write("Overwriting clipboard in...0 \r")
    sys.stdout.write("\n")
    pyperclip.copy("z" * 2 * password_length)


class PGen(object):
    def __init__(self, config_path, algorithm_version):
        # The values below are set in self.parse_config_data(...)
        self.default_length = None
        self.default_prefix = None
        self.salt = None
        self.hashing_algorithm = None
        self.seconds_until_overwrite = None
        self.pseudo_base64_map = None

        # Actual __init__ logic
        config_data = read_config(config_path)
        self._config_path = config_path
        self._version = (
            algorithm_version
            or config_data.get("default_algorithm_version")
            or DEFAULT_VERSION
        )
        self.parse_config_data(config_data)

    def parse_config_data(self, yaml_content):
        """Parses data from the configuration file.

        Args:
            yaml_content (dict): Content of the configuration file
        """
        possible_settings = [
            "default_algorithm_version",
            "default_length",
            "default_prefix",
            "salt",
            "hashing_algorithm",
            "seconds_until_overwrite",
        ]
        if self._version >= 2:
            possible_settings.append("pseudo_base64_map")

        try:
            # All possible setting must be present for the default
            # algorithm version (but are not required for other_algorithm_defaults)
            for setting in possible_settings:
                setattr(self, setting, yaml_content[setting])
        except KeyError:
            raise KeyError(
                'The config file "{0}" does not contain entries for one or more of the following '
                'required settings: "{1}"'.format(
                    self._config_path, '", "'.join(possible_settings)
                )
            )

        # Check for version specific defaults
        if self._version in yaml_content.get("other_algorithm_defaults", []):
            logging.debug(
                'Loading "other_algorithm_defaults" for version = {}'.format(
                    self._version
                )
            )
            for setting in possible_settings:
                if setting in yaml_content:
                    setattr(self, setting, yaml_content[setting])

    def _get_length(self, cmd_line_length):
        """Gets the length for the generated password.

        Args:
            cmd_line_length (int): The length value passed in via the command line (None if omitted)
        Returns:
            The length value to be used by passgify
        """
        prefix_len_error = 'Length must be a positive integer, but "{0}" was provided for the length {1}'

        if cmd_line_length is None:
            len_error = ValueError(
                prefix_len_error.format(
                    self.default_length,
                    "in the config file {}".format(self._config_path),
                )
            )
            try:
                length = int(self.default_length)
            except ValueError:
                raise len_error
        else:
            len_error = ValueError(
                prefix_len_error.format(cmd_line_length, "via the command line")
            )
            try:
                length = int(cmd_line_length)
            except ValueError:
                raise len_error
        if length < 1:
            raise len_error
        return length

    def _get_hash_method(self):
        """Gets the chosen hashing algorithm."""
        try:
            hash_method = getattr(hashlib, self.hashing_algorithm)
        except AttributeError:
            raise AttributeError(
                '"{0}" is not a hashing algorithm supported by hashlib. Please edit or delete the '
                "configuration file located here: {1}. Here is the list of supported algorithms: {2}".format(
                    self.hashing_algorithm,
                    self._config_path,
                    repr(hashlib.algorithms_available),
                )
            )
        return hash_method

    def _validate_overwrite_seconds(self):
        """Validates the number of seconds to wait until overwriting the password in the clipboard."""
        overwrite_error = ValueError(
            'Seconds to wait until overwriting the password must be a positive integer. "{0}" was provided for this '
            'value in the config file, "{1}"'.format(
                self.seconds_until_overwrite, self._config_path
            )
        )
        try:
            int(self.seconds_until_overwrite)
        except ValueError:
            raise overwrite_error
        if self.seconds_until_overwrite <= 0:
            raise overwrite_error

    def generate_password(self, service_id, prefix, length, decrypt_disk_image_path):
        """Generate the password based on supplied parameters.

        Args:
            service_id (string): service id used to generate the password from a hashing algorithm
            prefix (string): prefix of generated password
            length (positive int): length of generated password
            config_path (string): yaml configuration file path
            decrypt_disk_image_path (boolean): indicates whether to decrypt a disk image
        """
        # Get default prefix if None is set
        if prefix is None:
            prefix = self.default_prefix

        length = self._get_length(length)
        hash_method = self._get_hash_method()
        self._validate_overwrite_seconds()

        # Get Secret Key
        secret_key = getpass.getpass(prompt="Secret Key: ")

        # Generate the "full length" password
        hash_alg_result = hash_method(
            (service_id + self.salt + secret_key).encode("utf-8")
        ).hexdigest()
        if self._version >= 2:
            full_password = prefix + pb64_digest(
                hash_alg_result, self.pseudo_base64_map, self._version
            )
        else:
            full_password = prefix + hash_alg_result

        # Check that requested password length isn't too long
        if len(full_password) < length:
            raise ValueError(
                "The max password length for your chosen prefix is {0} characters".format(
                    len(full_password)
                )
            )

        # Check if the user wants to decrypt a disk image
        if decrypt_disk_image_path is not None:
            decrypt_image(decrypt_disk_image_path, full_password[:length])
        else:
            pyperclip.copy(full_password[:length])
            overwrite_password(length, self.seconds_until_overwrite)


def parse_args():
    try:
        version = pkg_resources.require(PROGRAM_NAME)[0].version
    except pkg_resources.DistributionNotFound:
        version = '(Install with "sudo python setup.py install" to get program version number)'

    parser = argparse.ArgumentParser(prog=PROGRAM_NAME, description=PROGRAM_PURPOSE)
    parser.add_argument(
        "-V",
        "--program_version",
        action="version",
        version="{0} {1}".format(PROGRAM_NAME, version),
    )
    parser.add_argument(
        "service_id",
        help="[REQUIRED] A service identifier. It can be anything really, as long as "
        "its unique. A common choice is the name of the service, such as a website name (e.g. google, "
        "amazon)",
    )
    parser.add_argument(
        "-v",
        "--algorithm_version",
        type=int,
        help="[OPTIONAL] Selects the version "
        "of the passgify algorithm to use. By default, uses the latest "
        "version (version {})".format(DEFAULT_VERSION),
    )
    parser.add_argument(
        "-c",
        "--config_path",
        default=DEFAULT_CONFIG_FILE,
        help="[OPTIONAL] Path to the YAML "
        "configuration file for this program. (default = %(default)s)",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        help="[OPTIONAL] Length of hashed password including its prefix",
    )
    parser.add_argument("-p", "--prefix", help="[OPTIONAL] Prefix to hashed password")
    parser.add_argument(
        "-d",
        "--decrypt_disk_image_path",
        metavar="IMAGE_PATH",
        help="[OPTIONAL] "
        "Instead of copying the generated password to the clipboard, use it to open a disk image "
        "located at PATH (Only supported for disk images on Mac OS X currently.",
    )
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    pgen = PGen(args.config_path, args.algorithm_version)
    pgen.generate_password(
        args.service_id, args.prefix, args.length, args.decrypt_disk_image_path
    )


if __name__ == "__main__":
    main()
