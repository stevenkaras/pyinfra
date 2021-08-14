import re

from pyinfra.api import FactBase


ASDF_PLUGIN_PATTERN = r"[a-zA-Z0-9\-]+"
ASDF_PLUGIN_LINE_PATTERN = rf"^({ASDF_PLUGIN_PATTERN})$"


class AsdfPlugins(FactBase):
    """
    Returns a set of installed asdf plugins

    .. code:: python

        {
            'nodejs',
            'python',
            'ruby',
        }
    """

    command = "asdf plugin list"
    requires_command = "asdf"

    default = set

    def process(self, output):
        plugins = set()

        for line in output:
            matches = re.match(ASDF_PLUGIN_LINE_PATTERN, line)

            if matches:
                plugins.add(matches.group(1))

        return plugins


# NOTE: some asdf plugins will happily "install" nonsense versions such as "--list" and "--help"
ASDF_VERSION_PATTERN = r"[a-zA-Z0-9\.][a-zA-Z0-9\.\-_+]*"
ASDF_PACKAGE_PATTERN = rf"^\s*({ASDF_VERSION_PATTERN})"
ASDF_NO_VERSIONS_PATTERN = r"^\s*No versions installed$"


class AsdfPackages(FactBase):
    """
    Returns a dict of installed asdf packages (runtimes)

    .. code:: python

        {
            'plugin_name': ['version'],
        }
    """

    command = "asdf list"
    requires_command = "asdf"

    default = dict

    def process(self, output):
        packages = {}
        current_plugin = None
        for line in output:
            plugin_match = re.match(ASDF_PLUGIN_LINE_PATTERN, line)

            if plugin_match:
                current_plugin = plugin_match.group(1)
                packages.setdefault(current_plugin, set())
                continue

            no_versions_match = re.match(ASDF_NO_VERSIONS_PATTERN, line)
            if no_versions_match:
                continue

            package_match = re.match(ASDF_PACKAGE_PATTERN, line)
            if package_match:
                packages[current_plugin].add(package_match.group(1))
                continue

        return packages


ASDF_CURRENT_PATTERN = rf"^\s*({ASDF_PLUGIN_PATTERN})\s+({ASDF_VERSION_PATTERN})\s+.*$"


class AsdfCurrent(FactBase):
    """
    Returns a dict of asdf packages and their currently selected global versions

    .. code:: python

        {
            'plugin_name': 'version',
        }
    """

    command = "asdf current"
    requires_command = "asdf"

    default = dict

    def process(self, output):
        packages = {}
        for line in output:
            current_match = re.match(ASDF_CURRENT_PATTERN, line)
            if current_match:
                package, version = current_match.groups()
                packages[package] = version
        return packages
