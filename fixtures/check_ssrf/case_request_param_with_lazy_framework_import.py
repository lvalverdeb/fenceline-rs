import urllib.request


def view(request):
    # A framework import anywhere in the module, even a lazy one inside a
    # function, makes ``request`` web input throughout the module.
    from django.http import HttpResponse

    with urllib.request.urlopen(request.GET["u"]) as resp:
        return HttpResponse(resp.read())
