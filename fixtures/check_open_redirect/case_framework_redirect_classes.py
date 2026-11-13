from django.http import HttpResponseRedirect
from starlette.responses import RedirectResponse
from aiohttp import web


def django_view(request):
    return HttpResponseRedirect(request.GET.get("next"))


async def starlette_view(request):
    return RedirectResponse(url=request.query_params["next"])


def fixed():
    return HttpResponseRedirect("/home")


async def aio(request):
    raise web.HTTPFound(location=request.query["next"])
