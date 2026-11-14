import urllib.request


def forward(request):
    # Nothing in this module imports a web framework, so ``request`` is this
    # library's own outbound request object, not web input.
    with urllib.request.urlopen(request.url) as resp:
        return resp.read()


class Signer:
    def __init__(self, request):
        self.request = request
        self.request_timeout = 30

    def send(self):
        return urllib.request.urlopen(self.request.url, timeout=self.request_timeout)
