"""Strict v2 benchmark coordinator primitives."""

from .model import ExperimentSpecV2, ImmutableIdentityManifest, PathProfile
from .spec import load_experiment_spec

__all__ = [
    "ExperimentSpecV2",
    "ImmutableIdentityManifest",
    "PathProfile",
    "load_experiment_spec",
]

__version__ = "2.0.0"
