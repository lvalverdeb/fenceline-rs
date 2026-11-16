from django.shortcuts import redirect
from django.urls import reverse


def login_required_view(request):
    return redirect(reverse("account_login") + "?next=" + request.path)


def no_perm(request):
    return redirect(f"{reverse('account_login')}?next={request.GET.get('next', '/')}")


def jump(request):
    return redirect(request.GET["next"] + reverse("index"))
