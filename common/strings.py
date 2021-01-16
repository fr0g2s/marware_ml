import string
import os.path
import re

class Strings(object):
    # Strings
    MAX_FILESIZE = 16 * 1024 * 1024
    MAX_STRINGCNT = 10000
    MAX_STRINGLEN = 512
    DEBUG = 0

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings or None
        """
        self.key = "strings"
        strings = []
        if not os.path.exists(self.file_path):
            if(DEBUG):
               print(f"File does not exist: self.file_path")

        try:
            data = open(self.file_path, "rb").read(self.MAX_FILESIZE)
        except (IOError, OSError) as e:
            return None

        for s in re.findall(b"[\x1f-\x7e]{6,}", data):
            strings.append(s.decode("utf-8"))
        for s in re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", data):
            strings.append(s.decode("utf-16le"))

        # Now limit the amount & length of the strings.
        strings = strings[:self.MAX_STRINGCNT]
        for idx, s in enumerate(strings):
            strings[idx] = s[:self.MAX_STRINGLEN]

        return strings
