from pyinfra.api import operation
from pyinfra.facts.asdf import AsdfPlugins, AsdfPackages, AsdfCurrent

from .util.packaging import (
    ensure_versionless_packages,
    ensure_multi_packages,
    parse_package_version,
)


@operation(is_idempotent=False)
def upgrade_plugins(state=None, host=None):
    """
    Upgrades all asdf plugins.
    """

    yield "asdf plugin update --all"


@operation
def plugins(
    plugins=None,
    present=True,
    upgrade=False,
    state=None,
    host=None,
):
    """
    Add/remove asdf plugins.

    + plugins: list of plugins to ensure
    + present: whether the plugins should be installed
    + upgrade: run ``asdf plugin update`` before installing plugins

    Examples:

    .. code:: python

        # Upgrade all plugins and install plugins
        asdf.plugins(
            name='Install Ruby and Python',
            plugins=['ruby', 'python'],
            upgrade=True,
        )
    """

    if upgrade:
        yield upgrade_plugins(state=state, host=host)

    yield ensure_versionless_packages(
        host,
        packages=plugins,
        current_packages=host.get_fact(AsdfPlugins),
        present=present,
        install_command="asdf plugin add",
        uninstall_command="asdf plugin remove",
        rollup_commands=False,
    )


@operation
def packages(
    packages=None,
    present=True,
    state=None,
    host=None,
):
    """
    Add/remove asdf packages.

    + packages: list of packages to ensure
    + present: whether the packages should be installed

    Versions:
        Package versions can be specified like this: ``<pkg> <version>``.

    Examples:

    .. code:: python

        # Update package list and install packages
        asdf.packages(
            name='Install Python 2.7.12',
            packages=["python 2.7.12"],
        )

        # Install the latest versions of packages (always check)
        asdf.packages(
            name='Install latest Ruby',
            packages=['ruby'],
        )
    """
    yield ensure_multi_packages(
        host,
        packages=packages,
        current_packages=host.get_fact(AsdfPackages),
        present=present,
        install_command="asdf install",
        uninstall_command="asdf uninstall",
        latest="latest",
        spec_version_join="=",
        command_version_join=" ",
        rollup_commands=False,
    )


@operation
def current(packages, state=None, host=None):
    """
    Set a current version globally

    + packages: a list of packages to set the current version for (defaults to latest)

    Versions:
        Package versions can be specified like this: ``<pkg>=<version>``.

    Examples:

    .. code:: python

        # Set the current python version to the latest
        asdf.current(
            name='Set current versions',
            packages=["python=2.7.12", "ruby"],
        )
    """
    for package in packages:
        package_name, version = parse_package_version(package)

        if version == "latest":
            installed_versions = host.get_fact(AsdfPackages).get(package_name, [])
            if not installed_versions:
                host.noop(f"no versions of {package_name} installed")
                continue
            desired_version = sorted(installed_versions, reverse=True)[0]
        else:
            desired_version = version

        current_versions = host.get_fact(AsdfCurrent)
        if current_versions.get(package_name) != desired_version:
            yield f"asdf global {package_name} {version}"
            current_versions[package_name] = desired_version
        else:
            host.noop(
                f"asdf package {package_name} current version already set to {version}"
            )
            continue
