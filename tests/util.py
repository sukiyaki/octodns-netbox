class SimpleProvider:
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    id = "test"

    def __init__(self, id="test"):
        pass

    def populate(self, zone, source=False, lenient=False):
        pass

    def supports(self, record):
        return True

    def __repr__(self):
        return self.__class__.__name__
