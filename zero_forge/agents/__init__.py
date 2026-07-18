"""Agent package for ZeroForge."""

from . import smart_agent as _smart_agent
from .nuclei_support import register_nuclei_profile as _register_nuclei_profile

_register_nuclei_profile(_smart_agent)
