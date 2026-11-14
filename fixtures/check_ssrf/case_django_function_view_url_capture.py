import requests
from django.shortcuts import render


def fetch(request, host):
    return requests.get("http://" + host)


def fetch_stored(request, pk):
    target = Endpoint.objects.get(pk=pk)
    return requests.get(target.url)


def helper(host, request):
    return requests.get("http://" + host)
