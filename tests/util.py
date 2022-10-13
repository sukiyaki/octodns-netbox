import json
import os


def load_fixture(filename):
    """Load a fixture."""
    with open(
        os.path.join(os.path.dirname(__file__), "fixtures", filename), encoding="utf-8"
    ) as fp:
        data = json.load(fp)
    return data


class SimpleProvider(object):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(("A", "AAAA", "PTR"))
    id = "test"

    def __init__(self, id="test"):
        pass

    def populate(self, zone, source=False, lenient=False):
        pass

    def supports(self, record):
        return True

    def __repr__(self):
        return self.__class__.__name__
