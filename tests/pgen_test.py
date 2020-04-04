# -*- coding: utf-8 -*-
import mock
import pytest
import sys
from src import pgen

TEST_FPATH = "src.pgen"


@pytest.fixture
def pgen_obj():
    pg = pgen.PGen()
    pg.read_config = mock.MagicMock(return_value=True)
    # Mock default values
    pg.default_length = "not_an_int"
    pg.default_prefix = "&*"
    pg.salt = "abcd"
    pg.hash_alg = "sha512"
    pg.sec_til_overwrite = 10
    return pg


@pytest.mark.parametrize("length", ["", "blah", -5, 0, None])
def test_generate_password_bad_password_lengths(pgen_obj, length):
    # Testing inadmissible length values
    with pytest.raises(ValueError):
        pgen_obj.generate_password(
            service_id="blah",
            prefix=None,
            length=length,
            config_path="blah",
            decrypt_disk_image_path="blah",
        )


def test_generate_password_bad_hashing_alg(pgen_obj):
    # Testing bad hashing algorithm
    pgen_obj.algorithm = "not_a_hashlib_method"
    with pytest.raises(AttributeError):
        pgen_obj.generate_password(
            service_id="blah",
            prefix=None,
            length=20,
            config_path="blah",
            decrypt_disk_image_path="blah",
        )


@pytest.mark.parametrize("overwrite_seconds", ["not_an_int", -5])
def test_generate_password_bad_countdown_account(pgen_obj, overwrite_seconds):
    # Testing bad seconds until overwrite
    pgen_obj.sec_til_overwrite = overwrite_seconds
    with pytest.raises(ValueError):
        pgen_obj.generate_password(
            service_id="blah",
            prefix=None,
            length=20,
            config_path="blah",
            decrypt_disk_image_path="blah",
        )


def test_generate_password_too_long_length(pgen_obj):
    # Testing a password that is too long
    with mock.patch(
        TEST_FPATH + ".getpass.getpass", return_value="mock_secret_key"
    ), mock.patch(TEST_FPATH + ".pb64_digest", return_value="too_short"), pytest.raises(
        ValueError
    ):
        pgen_obj.generate_password(
            service_id="blah",
            prefix=None,
            length=20,
            config_path="blah",
            decrypt_disk_image_path="blah",
        )


@pytest.mark.parametrize("decrypt_disk_image_path", [None, "a_path"])
def test_generate_password_valid(pgen_obj, decrypt_disk_image_path):
    test_length = 7
    mock_overwrite = mock.MagicMock()
    with mock.patch(
        TEST_FPATH + ".getpass.getpass", return_value="mock_secret_key"
    ), mock.patch(
        TEST_FPATH + ".pb64_digest", return_value="mock_pb64_hash"
    ), mock.patch(
        TEST_FPATH + ".decrypt_image"
    ), mock.patch(
        TEST_FPATH + ".pyperclip.copy"
    ), mock.patch(
        TEST_FPATH + ".overwrite_countdown", mock_overwrite
    ):
        pgen_obj.generate_password(
            service_id="blah",
            prefix=None,
            length=test_length,
            config_path="blah",
            decrypt_disk_image_path=decrypt_disk_image_path,
        )
        if decrypt_disk_image_path:
            assert not mock_overwrite.called
        else:
            mock_overwrite.assert_called_with(test_length, pgen_obj.sec_til_overwrite)


@pytest.mark.parametrize("detect_error", [True, False])
def test__read_config_empty_config(detect_error):
    pg = pgen.PGen()
    fake_salt = "fake_salt"
    if detect_error:
        with pytest.raises(IOError):
            pg.read_config("")
    else:
        with mock.patch("{}.create_config_file"), mock.patch(
            TEST_FPATH + ".yaml.load",
            return_value={
                "salt": fake_salt,
                "default_length": None,
                "default_prefix": None,
                "hashing_algorithm": None,
                "seconds_until_overwrite": None,
                "pseudo_base64_map": None,
            },
        ):
            pg.read_config("")
            assert pg.salt == fake_salt


def test__read_config_mocked_config():
    pg = pgen.PGen()
    with mock.patch(TEST_FPATH + ".open"), mock.patch(
        TEST_FPATH + ".yaml.load", return_value={}
    ), pytest.raises(KeyError):
        pg.read_config("")


def test_create_config_file_bad_hash_alg():
    with mock.patch(TEST_FPATH + ".input", return_value="fake"), pytest.raises(
        AttributeError
    ):
        pgen.create_config_file("fake_config_path")


def test_create_config_file_bad_config_path():
    with mock.patch(TEST_FPATH + ".input", return_value=""), pytest.raises(IOError):
        pgen.create_config_file("")


def test_create_config_file_defaults():
    mock_open = mock.MagicMock()
    fake_config_path = "fake_config_path"
    with mock.patch(TEST_FPATH + ".input", return_value=""), mock.patch(
        TEST_FPATH + ".open", mock_open
    ):
        pgen.create_config_file(fake_config_path)
        mock_open.assert_called_with(fake_config_path, "r")


@pytest.mark.parametrize(
    "input_, output",
    [
        ("", ""),
        ("ab", ""),
        ("abc", "1t"),
        ("abcd", "1t"),
        ("abcde", "1t"),
        ("abcdef", "1ty6"),
    ],
)
def test_pb64_digest(input_, output):
    assert pgen.pb64_digest(input_) == output


def test_decrypt_image_not_darwin():
    with mock.patch(TEST_FPATH + ".sys", platform="not_darwin"), pytest.raises(
        NotImplementedError
    ):
        pgen.decrypt_image("", "")


def test_decrypt_image_is_darwin():
    mock_write = mock.MagicMock()
    fake_password = "fake_password"
    with mock.patch(TEST_FPATH + ".sys", platform="darwin"), mock.patch(
        TEST_FPATH + ".subprocess.Popen",
        return_value=mock.MagicMock(
            communicate=mock.MagicMock(return_value=("fake_output", "fake_error")),
            stdin=mock.MagicMock(write=mock_write),
        ),
    ):
        pgen.decrypt_image("", fake_password)
        mock_write.assert_called_with(fake_password)


def test_overwrite_countdown_value_err():
    with pytest.raises(ValueError):
        pgen.overwrite_countdown(-3, "blah")


@pytest.mark.parametrize("sec", [-99, -1, 0,])
def test_overwrite_countdown_negative_seconds(sec):
    with mock.patch("pyperclip.copy") as mock_pyperclip:
        pgen.overwrite_countdown(10, sec)
        assert mock_pyperclip.call_count == 1


def test_overwrite_countdown_ten_seconds():
    with mock.patch("time.sleep") as mock_sleep, mock.patch("pyperclip.copy"):
        pgen.overwrite_countdown(99, 10)
        assert mock_sleep.call_count == 10


def test_main():
    with mock.patch("modules.pgen.PGen") as mock_pgen:
        pgen.main(mock.MagicMock())
        assert mock_pgen().generate_password.call_count == 1
