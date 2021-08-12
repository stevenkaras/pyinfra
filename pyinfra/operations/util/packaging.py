from __future__ import unicode_literals

import six
import shlex

from six import StringIO
from six.moves import shlex_quote
from six.moves.urllib.parse import urlparse

from typing import Union

from pyinfra.facts.files import File
from pyinfra.facts.rpm import RpmPackage


def parse_package_version(
    package: str, version_join: str = "=", latest: str = "latest"
) -> tuple[str, str]:
    """
    Extracts a package version from a package string

    If the version is not specified, it will return "latest" as the version
    """
    package_spec = package.rsplit(version_join, 1)
    if len(package_spec) == 1:
        package_name = package_spec[0]
        package_version = latest
    else:
        package_name, package_version = package_spec
    return package_name, package_version


def _quote_package_spec(
    packages: list[tuple[str, str]], command_version_join: str
) -> list[str]:
    package_specs = []
    for package_name, package_version in packages:
        if not package_version:
            package_spec = shlex.quote(package_name)
        elif command_version_join == " ":
            package_spec = f"{shlex.quote(package_name)} {shlex.quote(package_version)}"
        else:
            package_spec = shlex.quote(
                command_version_join.join((package_name, package_version))
            )
        package_specs.append(package_spec)
    return package_specs


def _issue_commands(command: str, specs, rollup_commands=False):
    if not specs:
        return

    if rollup_commands:
        yield f"{command} {' '.join(package_spec for package_spec in specs)}"
    else:
        for package_spec in specs:
            yield f"{command} {package_spec}"


def _issue_noops(host, packages, present=True):
    for package in packages:
        if isinstance(package, tuple):
            package = f"{package[0]} {package[1]}"

        if present:
            host.noop(f"package {package} already installed")
        else:
            host.noop(f"package {package} is not installed")


def ensure_single_packages(
    host,
    packages: Union[list[str], set[str]],
    current_packages: dict[str, str],
    present: bool,
    upgrade_to_latest: bool,
    install_command: str,
    uninstall_command: str,
    upgrade_command: str,
    latest: str = "",
    spec_version_join: str = "=",
    command_version_join: str = "=",
    rollup_commands: bool = True,
):
    """
    Handles this common scenario:

    + We have a list of packages(/version) to ensure
    + We have a map of existing package -> version
    + We have the common command bits (install, uninstall, version "joiner")
    + Outputs commands to ensure our desired packages/versions
    + Optionally upgrades packages w/o specified version when present
    + Only a single version of the same package can be installed simultaneously

    Args:
        packages: list of packages or package/versions
        current_packages: dict of package names to currently installed versions
        present: whether packages should exist or not
        upgrade_to_latest: upgrade a package if the version is unspecified
        install_command: command to prefix to packages to install
        uninstall_command: as above, but for uninstalling packages
        latest: the string used to indicate to the package manager to install the latest version
        spec_version_join: the "joiner" for specifying versions, ie ``=`` for ``<package>=<version>``
        command_version_join: the "joiner" for installing versions, ie ``=`` for ``<package>=<version>``. A single space
          will be interpreted to mean that the version is a second argument.
        rollup_commands: whether to issue a single command for all changes or multiple
    """
    if not packages:
        return

    if isinstance(packages, str):
        packages = [packages]

    desired_packages = {}
    for package in packages:
        package_name, package_version = parse_package_version(
            package, version_join=spec_version_join, latest=latest
        )
        desired_packages[package_name] = package_version

    diff_packages = []
    upgrade_packages = []
    noop_packages = []

    for package_name, desired_version in desired_packages.items():
        if package_name not in current_packages:
            diff_packages.append((package_name, package_version))
        elif package_version != current_packages[package_name] and present:
            if package_version == latest and not upgrade_to_latest:
                noop_packages.append((package_name, package_version))
                continue
            upgrade_packages.append((package_name, package_version))
        else:
            noop_packages.append((package_name, package_version))

    # when declaring unwanted packages, we can simply swap the operations around
    if not present:
        diff_packages, noop_packages = noop_packages, diff_packages

    # Emit noop messages
    _issue_noops(host, noop_packages, present=present)

    # figure out the quoting
    diff_specs = _quote_package_spec(diff_packages, command_version_join)
    upgrade_specs = _quote_package_spec(upgrade_packages, command_version_join)

    command = install_command if present else uninstall_command
    yield _issue_commands(
        command=command, specs=diff_specs, rollup_commands=rollup_commands
    )
    yield _issue_commands(
        command=upgrade_command, specs=upgrade_specs, rollup_commands=rollup_commands
    )

    for package_name, package_version in diff_packages:
        if present:
            current_packages[package_name] = package_version
        else:
            current_packages.pop(package_name)

    for package_name, package_version in upgrade_packages:
        current_packages[package_name] = package_version


def ensure_multi_packages(
    host,
    packages: Union[list[str], set[str]],
    current_packages: dict[str, set[str]],
    present: bool,
    install_command: str,
    uninstall_command: str,
    latest: str = "",
    spec_version_join: str = "=",
    command_version_join: str = "=",
    rollup_commands: bool = True,
):
    """
    Handles this common scenario:

    + We have a list of packages(/version) to ensure
    + We have a map of existing package -> version
    + We have the common command bits (install, uninstall, version "joiner")
    + Outputs commands to ensure our desired packages/versions
    + Optionally upgrades packages w/o specified version when present
    + Multiple versions of the same package can be installed simultaneously

    Args:
        packages: list of packages or package/versions
        current_packages: dict of package names to currently installed versions
        present: whether packages should exist or not
        install_command: command to prefix to packages to install
        uninstall_command: as above, but for uninstalling packages
        latest: the string used to indicate to the package manager to install the latest version
        spec_version_join: the "joiner" for specifying versions, ie ``=`` for ``<package>=<version>``
        command_version_join: the "joiner" for installing versions, ie ``=`` for ``<package>=<version>``. A single space
          will be interpreted to mean that the version is a second argument.
        rollup_commands: whether to issue a single command for all changes or multiple
    """
    if not packages:
        return

    if isinstance(packages, str):
        packages = [packages]

    desired_packages: dict[str, set[str]] = {}
    for package in packages:
        package_name, package_version = parse_package_version(
            package, version_join=spec_version_join, latest=latest
        )
        desired_packages.setdefault(package_name, set()).add(package_version)

    diff_packages = []
    noop_packages = []

    for package_name, desired_versions in desired_packages.items():
        current_versions = current_packages.get(package_name, set())
        diff_versions = desired_versions - current_versions
        noop_versions = desired_versions & current_versions
        diff_packages += [(package_name, version) for version in diff_versions]
        noop_packages += [(package_name, version) for version in noop_versions]

    # when declaring unwanted packages, we can simply swap the operations around
    if not present:
        diff_packages, noop_packages = noop_packages, diff_packages

    # Emit noop messages
    _issue_noops(host, noop_packages, present=present)

    # figure out the quoting
    diff_specs = _quote_package_spec(diff_packages, command_version_join)

    command = install_command if present else uninstall_command
    yield _issue_commands(
        command=command, specs=diff_specs, rollup_commands=rollup_commands
    )

    for package_name, package_version in diff_packages:
        if present:
            current_packages.setdefault(package_name, set()).add(package_version)
        else:
            current_packages.get(package_name, set()).discard(package_version)


def ensure_versionless_packages(
    host,
    packages: Union[list[str], set[str]],
    current_packages: set[str],
    present: bool,
    install_command: str,
    uninstall_command: str,
    rollup_commands: bool = True,
):
    """
    Handles this common scenario:

    + We have a list of packages to ensure
    + We have a list of existing packages
    + We have the common command bits (install, uninstall)
    + Outputs commands to ensure our desired packages

    Args:
        packages: list of packages or package/versions
        current_packages: fact returning list of package names
        present: whether packages should exist or not
        install_command: command to prefix to list of packages to install
        uninstall_command: as above for uninstalling packages
        rollup_commands: whether to issue a single command for all changes or multiple
    """
    if not packages:
        return

    if isinstance(packages, str):
        packages = [packages]

    desired_packages = set(packages)

    diff_packages = desired_packages - current_packages
    noop_packages = desired_packages & current_packages

    if not present:
        diff_packages, noop_packages = noop_packages, diff_packages

    _issue_noops(host, noop_packages, present=present)

    diff_specs = [shlex.quote(package) for package in diff_packages]

    command = install_command if present else uninstall_command
    yield _issue_commands(
        command=command, specs=diff_specs, rollup_commands=rollup_commands
    )

    if present:
        current_packages.update(diff_packages)
    else:
        current_packages.difference_update(diff_packages)


def _has_package(package, packages, expand_package_fact=None, match_any=False):
    def in_packages(pkg):
        if isinstance(pkg, list):
            return pkg[0] in packages and pkg[1] in packages[pkg[0]]
        return pkg in packages

    packages_to_check = [package]
    if expand_package_fact:
        packages_to_check = expand_package_fact(package) or packages_to_check

    checks = (in_packages(pkg) for pkg in packages_to_check)
    if match_any:
        return any(checks)
    return all(checks)


def ensure_packages(
    host, packages, current_packages, present,
    install_command, uninstall_command,
    latest=False, upgrade_command=None,
    version_join=None, lower=True,
    expand_package_fact=None,
):
    '''
    Handles this common scenario:

    + We have a list of packages(/versions) to ensure
    + We have a map of existing package -> versions
    + We have the common command bits (install, uninstall, version "joiner")
    + Outputs commands to ensure our desired packages/versions
    + Optionally upgrades packages w/o specified version when present

    Args:
        packages (list): list of packages or package/versions
        current_packages (fact): fact returning dict of package names -> version
        present (bool): whether packages should exist or not
        install_command (str): command to prefix to list of packages to install
        uninstall_command (str): as above for uninstalling packages
        latest (bool): whether to upgrade installed packages when present
        upgrade_command (str): as above for upgrading
        version_join (str): the package manager specific "joiner", ie ``=`` for \
            ``<apt_pkg>=<version>``
        lower (bool): whether to lowercase package names
    '''

    if packages is None:
        return

    # Accept a single package as string
    if isinstance(packages, six.string_types):
        packages = [packages]

    # Lowercase packaging?
    if lower:
        packages = [
            package.lower()
            for package in packages
        ]

    # Version support?
    if version_join:
        # Split where versions present
        packages = [
            package.rsplit(version_join, 1)
            for package in packages
        ]

        # Covert to either string or list
        packages = [
            package[0] if len(package) == 1
            else package
            for package in packages
        ]

    # Diff the ensured packages against the remote state/fact
    diff_packages = []

    # Packages to upgrade? (install only)
    upgrade_packages = []

    # Installing?
    if present is True:
        for package in packages:
            # String version, just check if not existing
            if not _has_package(package, current_packages, expand_package_fact):
                diff_packages.append(package)

            else:
                # Present packages w/o version specified - for upgrade if latest
                if isinstance(package, six.string_types):
                    upgrade_packages.append(package)

                if not latest:
                    pkg_key = package[0] if isinstance(package, list) else package
                    if pkg_key in current_packages:
                        host.noop('package {0} is installed ({1})'.format(
                            package, ', '.join(current_packages[pkg_key]),
                        ))
                    else:
                        host.noop('package {0} is installed'.format(package))

    # Uninstalling?
    else:
        for package in packages:
            # String version, just check if existing
            if _has_package(package, current_packages, expand_package_fact, match_any=True):
                diff_packages.append(package)

            else:
                host.noop('package {0} is not installed'.format(package))

    # Convert packages back to string(/version)
    diff_packages = [
        version_join.join(package)
        if isinstance(package, list)
        else package
        for package in diff_packages
    ]

    if diff_packages:
        command = install_command if present else uninstall_command

        yield '{0} {1}'.format(
            command,
            ' '.join([shlex_quote(pkg) for pkg in diff_packages]),
        )

        for package in diff_packages:  # add/remove from current packages
            if present:
                version = 'unknown'
                if version_join:
                    bits = package.rsplit(version_join, 1)
                    package = bits[0]
                    if len(bits) == 2:
                        version = bits[1]
                current_packages[package] = [version]
            else:
                current_packages.pop(package, None)

    if latest and upgrade_command and upgrade_packages:
        yield '{0} {1}'.format(
            upgrade_command,
            ' '.join([shlex_quote(pkg) for pkg in upgrade_packages]),
        )


def ensure_rpm(state, host, files, source, present, package_manager_command):
    original_source = source

    # If source is a url
    if urlparse(source).scheme:
        # Generate a temp filename (with .rpm extension to please yum)
        temp_filename = '{0}.rpm'.format(state.get_temp_filename(source))

        # Ensure it's downloaded
        yield files.download(source, temp_filename, state=state, host=host)

        # Override the source with the downloaded file
        source = temp_filename

    # Check for file .rpm information
    info = host.get_fact(RpmPackage, name=source)
    exists = False

    # We have info!
    if info:
        current_package = host.get_fact(RpmPackage, name=info['name'])
        if current_package and current_package['version'] == info['version']:
            exists = True

    # Package does not exist and we want?
    if present and not exists:
        # If we had info, always install
        if info:
            yield 'rpm -i {0}'.format(source)

        # This happens if we download the package mid-deploy, so we have no info
        # but also don't know if it's installed. So check at runtime, otherwise
        # the install will fail.
        else:
            yield 'rpm -q `rpm -qp {0}` 2> /dev/null || rpm -i {0}'.format(source)

    # Package exists but we don't want?
    elif exists and not present:
        yield '{0} remove -y {1}'.format(package_manager_command, info['name'])

    else:
        host.noop('rpm {0} is {1}'.format(
            original_source,
            'installed' if present else 'not installed',
        ))


def ensure_yum_repo(
    state, host, files,
    name_or_url, baseurl, present, description, enabled, gpgcheck, gpgkey,
    repo_directory='/etc/yum.repos.d/',
    type_=None,
):
    url = None
    url_parts = urlparse(name_or_url)
    if url_parts.scheme:
        url = name_or_url
        name_or_url = url_parts.path.split('/')[-1]
        if name_or_url.endswith('.repo'):
            name_or_url = name_or_url[:-5]

    filename = '{0}{1}.repo'.format(repo_directory, name_or_url)

    # If we don't want the repo, just remove any existing file
    if not present:
        yield files.file(filename, present=False, state=state, host=host)
        return

    # If we're a URL, download the repo if it doesn't exist
    if url:
        if not host.get_fact(File, path=filename):
            yield files.download(url, filename, state=state, host=host)
        return

    # Description defaults to name
    description = description or name_or_url

    # Build the repo file from string
    repo_lines = [
        '[{0}]'.format(name_or_url),
        'name={0}'.format(description),
        'baseurl={0}'.format(baseurl),
        'enabled={0}'.format(1 if enabled else 0),
        'gpgcheck={0}'.format(1 if gpgcheck else 0),
    ]

    if type_:
        repo_lines.append('type={0}'.format(type_))

    if gpgkey:
        repo_lines.append('gpgkey={0}'.format(gpgkey))

    repo_lines.append('')
    repo = '\n'.join(repo_lines)
    repo = StringIO(repo)

    # Ensure this is the file on the server
    yield files.put(repo, filename, state=state, host=host)
