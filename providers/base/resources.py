"""Resources and CompositeResources — base classes for resource collectors.

:class:`Resources` is an abstract ``dict`` subclass.  Each instance
represents a collection of cloud resources of a single type
(e.g. all S3 buckets, all IAM users).  Resource IDs are keys; config
dicts are values.

:class:`CompositeResources` extends :class:`Resources` to support
hierarchical child resources fetched concurrently via ``asyncio``.

Example hierarchy (AWS EC2)::

    EC2Regions(CompositeResources)
      └── EC2VPCs(CompositeResources)
            └── SecurityGroups(Resources)

Each :class:`CompositeResources` declares its child types in ``_children``.
After fetching its own items it fans out concurrent ``fetch_all()`` calls
for every child against every parent item, storing results under the
child's ``KEY`` in the parent's config dict.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type


class Resources(dict, ABC):
    """Abstract dict-like collector for a single cloud resource type.

    Subclasses implement :meth:`fetch_all` to populate ``self`` with
    ``{resource_id: config_dict}`` entries.

    Class attributes
    ----------------
    KEY:    str
        Key under which this collection is stored in its parent's config dict.
    REGION: bool
        Set ``True`` if this resource is region-scoped.
    """

    KEY:    str  = ""      # storage key in parent config dict
    REGION: bool = False   # True if region-scoped

    def __init__(self, facade: Any = None, verbose: bool = False) -> None:
        super().__init__()
        self.facade  = facade
        self.verbose = verbose

    @abstractmethod
    async def fetch_all(self) -> None:
        """Populate this dict with ``{id: config}`` entries."""

    def _add(self, resource_id: str, config: Dict[str, Any]) -> None:
        """Store *config* under *resource_id*."""
        self[resource_id] = config

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(f"      [~] [{self.__class__.__name__}] {msg}")

    def _warn(self, msg: str) -> None:
        print(f"      [!] [{self.__class__.__name__}] WARNING: {msg}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(count={len(self)})"


class CompositeResources(Resources, ABC):
    """A :class:`Resources` node that also fetches child resource types.

    Declare child resource classes in the ``_children`` class attribute::

        class EC2Regions(CompositeResources):
            KEY = "regions"
            _children = [EC2VPCs]

            async def _fetch_all_items(self) -> None:
                for region in await self.facade.get_regions():
                    self._add(region["RegionName"], {"name": region["RegionName"]})

    Child data is stored under ``child.KEY`` in each parent config dict,
    alongside a ``<KEY>_count`` integer.
    """

    #: Child resource types to fetch for every item in this collection.
    _children: List[Type[Resources]] = []

    # ------------------------------------------------------------------
    # fetch_all: top-level items first, then children concurrently
    # ------------------------------------------------------------------

    async def fetch_all(self) -> None:
        """Fetch this level's items, then concurrently fetch all children."""
        await self._fetch_all_items()
        if self._children:
            await self._fetch_children_of_all_resources()

    @abstractmethod
    async def _fetch_all_items(self) -> None:
        """Populate this dict with top-level ``{id: config}`` entries (no children)."""

    # ------------------------------------------------------------------
    # Concurrent child fetching
    # ------------------------------------------------------------------

    async def _fetch_children_of_all_resources(self) -> None:
        """For each item, concurrently fetch all declared child resource types."""
        tasks = [
            self._fetch_child(res_id, res_cfg, child_cls)
            for res_id, res_cfg in self.items()
            for child_cls in self._children
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_child(
        self,
        resource_id:     str,
        resource_config: Dict[str, Any],
        child_cls:       Type[Resources],
    ) -> None:
        """Instantiate *child_cls*, fetch its data, store under parent config."""
        child = child_cls(facade=self.facade, verbose=self.verbose)
        try:
            await child.fetch_all()
        except Exception as exc:  # noqa: BLE001
            self._warn(
                f"{child_cls.__name__} fetch failed "
                f"for '{resource_id}': {exc}"
            )
            return

        key = child_cls.KEY or child_cls.__name__.lower()
        resource_config[key]               = dict(child)
        resource_config[f"{key}_count"]    = len(child)
