import os
import sys

from dvc import command


class Dvc:
    @staticmethod
    def check_installed():
        return os.path.isdir(".dvc")

    @staticmethod
    def install():
        command.init()


__all__ = ["Dvc"]
