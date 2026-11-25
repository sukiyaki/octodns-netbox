"""Hypothesis profiles for tests/test_properties.py.

The default profile, "ci", runs the same examples on every run, so a CI run is
short and a failure in it reproduces on any machine. "thorough" runs more
examples, with new data on each run. CONTRIBUTING.md shows how to select it.
"""

from hypothesis import settings

# A deadline would fail an example that a slow CI machine runs slowly.
settings.register_profile(
    "ci", max_examples=50, derandomize=True, deadline=None, database=None
)
settings.register_profile("thorough", max_examples=2000, deadline=None)
settings.load_profile("ci")
