"""
Firmware Versioning
===================

Semantic versioning and upgrade policy management for firmware releases.

Provides:

* :class:`SemanticVersion` — an immutable, comparable representation of a
  `SemVer 2.0 <https://semver.org/>`_ version string.
* :class:`VersionManager` — policy engine that governs which upgrade /
  downgrade paths are permitted and suggests next versions.

Usage::

    from app.firmware.versioning import SemanticVersion, VersionManager

    v = SemanticVersion("1.2.3")
    print(v.bump_minor())  # 1.3.0

    mgr = VersionManager(allow_downgrade=False)
    mgr.register_version("fw-001", "1.0.0")
    mgr.register_version("fw-001", "1.1.0")
    result = mgr.check_upgrade_policy("fw-001", "1.0.0", "1.1.0")
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ── Semantic Version ─────────────────────────────────────────────────────────


class SemanticVersion:
    """Represents a `Semantic Version <https://semver.org/>`_ with full
    comparison support.

    Parses strings of the form ``MAJOR.MINOR.PATCH[-prerelease][+build]``.

    Parameters
    ----------
    version_str : str
        A valid semantic version string.

    Raises
    ------
    ValueError
        If *version_str* does not conform to the SemVer pattern.

    Examples
    --------
    >>> v = SemanticVersion("2.1.0-beta+build.42")
    >>> v.major, v.minor, v.patch
    (2, 1, 0)
    >>> v.pre_release
    'beta'
    """

    VERSION_PATTERN: str = (
        r"^(\d+)\.(\d+)\.(\d+)"
        r"(?:-(\w+(?:\.\w+)*))?"
        r"(?:\+(\w+(?:\.\w+)*))?$"
    )

    _regex = re.compile(VERSION_PATTERN)

    def __init__(self, version_str: str) -> None:
        match = self._regex.match(version_str.strip())
        if not match:
            raise ValueError(
                f"Invalid semantic version string: '{version_str}'. "
                "Expected format: MAJOR.MINOR.PATCH[-prerelease][+build]"
            )

        self.major: int = int(match.group(1))
        self.minor: int = int(match.group(2))
        self.patch: int = int(match.group(3))
        self.pre_release: Optional[str] = match.group(4)
        self.build_metadata: Optional[str] = match.group(5)
        self.original: str = version_str.strip()

    # ── String representations ───────────────────────────────────────────

    def __str__(self) -> str:
        """Return the canonical SemVer string (without build metadata)."""
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre_release:
            base += f"-{self.pre_release}"
        if self.build_metadata:
            base += f"+{self.build_metadata}"
        return base

    def __repr__(self) -> str:
        return f"SemanticVersion('{self}')"

    # ── Comparison helpers ───────────────────────────────────────────────

    def _comparison_tuple(self) -> tuple:
        """Return a tuple used for ordering.

        Per SemVer spec, pre-release versions have *lower* precedence than
        the associated normal version.  Build metadata is ignored for
        precedence.
        """
        # A release (no pre-release) sorts *higher* than any pre-release
        # for the same numeric triple.  We achieve this by using a tuple
        # where (0, "") < (1, "") — so pre-release gets 0, release gets 1.
        if self.pre_release is not None:
            return (self.major, self.minor, self.patch, 0, self.pre_release)
        return (self.major, self.minor, self.patch, 1, "")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._comparison_tuple() == other._comparison_tuple()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._comparison_tuple() < other._comparison_tuple()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._comparison_tuple() <= other._comparison_tuple()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._comparison_tuple() > other._comparison_tuple()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._comparison_tuple() >= other._comparison_tuple()

    def __hash__(self) -> int:
        return hash(self._comparison_tuple())

    # ── Upgrade classification ───────────────────────────────────────────

    def is_compatible_upgrade(self, target: SemanticVersion) -> bool:
        """Check if upgrading from *self* to *target* is API-compatible.

        A compatible (non-breaking) upgrade has the **same major version**
        and ``target >= self``.

        Parameters
        ----------
        target : SemanticVersion
            The version being upgraded to.

        Returns
        -------
        bool
        """
        return self.major == target.major and target >= self

    def is_major_upgrade(self, target: SemanticVersion) -> bool:
        """Check if *target* represents a major (breaking) version change.

        Parameters
        ----------
        target : SemanticVersion
            The version being upgraded to.

        Returns
        -------
        bool
        """
        return target.major > self.major

    # ── Bump helpers ─────────────────────────────────────────────────────

    def bump_major(self) -> SemanticVersion:
        """Return a new version with major incremented, minor & patch reset.

        Returns
        -------
        SemanticVersion
            e.g. ``1.2.3`` → ``2.0.0``
        """
        return SemanticVersion(f"{self.major + 1}.0.0")

    def bump_minor(self) -> SemanticVersion:
        """Return a new version with minor incremented, patch reset.

        Returns
        -------
        SemanticVersion
            e.g. ``1.2.3`` → ``1.3.0``
        """
        return SemanticVersion(f"{self.major}.{self.minor + 1}.0")

    def bump_patch(self) -> SemanticVersion:
        """Return a new version with patch incremented.

        Returns
        -------
        SemanticVersion
            e.g. ``1.2.3`` → ``1.2.4``
        """
        return SemanticVersion(f"{self.major}.{self.minor}.{self.patch + 1}")

    # ── Class methods ────────────────────────────────────────────────────

    @classmethod
    def is_valid(cls, version_str: str) -> bool:
        """Check whether *version_str* is a valid semantic version.

        Parameters
        ----------
        version_str : str
            The string to validate.

        Returns
        -------
        bool
        """
        return cls._regex.match(version_str.strip()) is not None


# ── Version Manager ──────────────────────────────────────────────────────────


class VersionManager:
    """Manages firmware version policies and upgrade paths.

    Parameters
    ----------
    allow_downgrade : bool
        Whether downgrading to a lower version is permitted.
    allow_major_upgrade : bool
        Whether crossing a major-version boundary is permitted.
    """

    def __init__(
        self,
        allow_downgrade: bool = False,
        allow_major_upgrade: bool = True,
    ) -> None:
        self._versions: dict[str, list[SemanticVersion]] = {}
        self.allow_downgrade: bool = allow_downgrade
        self.allow_major_upgrade: bool = allow_major_upgrade
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ── Registration ─────────────────────────────────────────────────────

    def register_version(self, firmware_id: str, version: str) -> SemanticVersion:
        """Register a new version for a firmware ID.

        The internal list is kept in ascending sorted order.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        version : str
            Semantic version string to register.

        Returns
        -------
        SemanticVersion
            The parsed version object.
        """
        sv = SemanticVersion(version)
        if firmware_id not in self._versions:
            self._versions[firmware_id] = []

        # Avoid duplicates.
        if sv not in self._versions[firmware_id]:
            self._versions[firmware_id].append(sv)
            self._versions[firmware_id].sort()
            self._logger.info(
                "Registered version %s for firmware '%s'", sv, firmware_id
            )
        else:
            self._logger.debug(
                "Version %s already registered for firmware '%s'",
                sv,
                firmware_id,
            )

        return sv

    # ── Queries ──────────────────────────────────────────────────────────

    def get_latest_version(self, firmware_id: str) -> Optional[SemanticVersion]:
        """Get the latest (highest) registered version for a firmware ID.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.

        Returns
        -------
        SemanticVersion or None
            The highest version, or ``None`` if no versions are registered.
        """
        versions = self._versions.get(firmware_id)
        if not versions:
            return None
        return versions[-1]

    def get_all_versions(self, firmware_id: str) -> list[SemanticVersion]:
        """Get all registered versions for a firmware ID, sorted ascending.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.

        Returns
        -------
        list[SemanticVersion]
        """
        return list(self._versions.get(firmware_id, []))

    # ── Policy checks ────────────────────────────────────────────────────

    def check_upgrade_policy(
        self,
        firmware_id: str,
        current_version: str,
        target_version: str,
    ) -> dict:
        """Check if an upgrade from *current_version* to *target_version*
        is allowed under the configured policy.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        current_version : str
            The version currently running on the device.
        target_version : str
            The version the device wants to upgrade to.

        Returns
        -------
        dict
            Keys:

            * ``allowed`` (bool) — whether the transition is permitted.
            * ``upgrade_type`` (str) — one of ``'patch'``, ``'minor'``,
              ``'major'``, ``'downgrade'``, or ``'same'``.
            * ``reason`` (str) — human-readable explanation.
            * ``current`` (str) — echo of *current_version*.
            * ``target`` (str) — echo of *target_version*.
        """
        current = SemanticVersion(current_version)
        target = SemanticVersion(target_version)

        # ── Determine upgrade type ───────────────────────────────────────
        if current == target:
            return {
                "allowed": True,
                "upgrade_type": "same",
                "reason": "Current and target versions are identical.",
                "current": current_version,
                "target": target_version,
            }

        if target < current:
            allowed = self.allow_downgrade
            return {
                "allowed": allowed,
                "upgrade_type": "downgrade",
                "reason": (
                    "Downgrade permitted by policy."
                    if allowed
                    else "Downgrade is not allowed by the current policy."
                ),
                "current": current_version,
                "target": target_version,
            }

        # target > current — determine granularity.
        if target.major > current.major:
            upgrade_type = "major"
            allowed = self.allow_major_upgrade
            reason = (
                "Major version upgrade permitted by policy."
                if allowed
                else "Major version upgrades are not allowed by the current policy."
            )
        elif target.minor > current.minor:
            upgrade_type = "minor"
            allowed = True
            reason = "Minor version upgrade permitted."
        else:
            upgrade_type = "patch"
            allowed = True
            reason = "Patch version upgrade permitted."

        return {
            "allowed": allowed,
            "upgrade_type": upgrade_type,
            "reason": reason,
            "current": current_version,
            "target": target_version,
        }

    def get_upgrade_path(
        self,
        firmware_id: str,
        current_version: str,
        target_version: str,
    ) -> list[str]:
        """Get the ordered list of registered versions between *current*
        and *target* (inclusive of target, exclusive of current).

        Useful for platforms that require sequential / incremental upgrades.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        current_version : str
            Starting version (excluded from the returned path).
        target_version : str
            Destination version (included in the returned path).

        Returns
        -------
        list[str]
            Version strings in ascending order forming the upgrade path.
        """
        current = SemanticVersion(current_version)
        target = SemanticVersion(target_version)

        all_versions = self.get_all_versions(firmware_id)
        path = [
            str(v) for v in all_versions if current < v <= target
        ]
        return path

    def suggest_next_version(
        self, firmware_id: str, bump_type: str = "patch"
    ) -> str:
        """Suggest the next version based on the bump type.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        bump_type : str
            One of ``'major'``, ``'minor'``, or ``'patch'``.

        Returns
        -------
        str
            The suggested next version string.

        Raises
        ------
        ValueError
            If *bump_type* is not one of the accepted values or no versions
            are registered for *firmware_id*.
        """
        latest = self.get_latest_version(firmware_id)
        if latest is None:
            raise ValueError(
                f"No versions registered for firmware '{firmware_id}'."
            )

        bump_type = bump_type.lower()
        if bump_type == "major":
            return str(latest.bump_major())
        if bump_type == "minor":
            return str(latest.bump_minor())
        if bump_type == "patch":
            return str(latest.bump_patch())

        raise ValueError(
            f"Invalid bump_type '{bump_type}'. Must be 'major', 'minor', or 'patch'."
        )
