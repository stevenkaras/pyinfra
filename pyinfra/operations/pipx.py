from pyinfra.api import operation
from pyinfra.facts.pipx import PipxApplications
from .util.packaging import ensure_single_packages


@operation(is_idempotent=False)
def upgrade(state=None, host=None):
    """
    Upgrades all pipx applications.
    """

    yield "pipx upgrade-all"


@operation
def applications(
    applications=None,
    present=True,
    upgrade_to_latest=False,
    state=None,
    host=None,
):
    """
    Add/remove pipx applications.

    + packages: list of packages to ensure
    + present: whether the packages should be installed
    + upgrade_to_latest: upgrade a package if the version is unspecified

    Versions:
        Package versions can be pinned like pipx: ``<pkg>=<version>``.

    Examples:

    .. code:: python

        pipx.applications(
            name='Install latest version of docker-compose',
            packages=['docker-compose'],
            upgrade=True,
        )

        pipx.applications(
            name='Ensure any version of docker-compose is present',
            packages=['docker-compose'],
        )
    """
    yield ensure_single_packages(
        host,
        packages=applications,
        current_packages=host.get_fact(PipxApplications),
        present=present,
        upgrade_to_latest=upgrade_to_latest,
        install_command="pipx install",
        uninstall_command="pipx uninstall",
        upgrade_command="pipx upgrade",
        rollup_commands=False,
    )
