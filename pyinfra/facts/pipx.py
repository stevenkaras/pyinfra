from pyinfra.api import FactBase
from pyinfra.facts.util.packaging import parse_packages


PIPX_PATTERN = r"^\s*package ([a-zA-Z\-][a-zA-Z\-0-9]*) ([0-9\.]+\-?[a-z0-9]*),"


class PipxApplications(FactBase):
    """
    Returns a dict of installed pipx applications

    .. code:: python

        {
            'package_name': ['version'],
        }
    """

    command = "pipx list"
    requires_command = "pipx"

    default = dict

    def process(self, output):
        return parse_packages(PIPX_PATTERN, output)
