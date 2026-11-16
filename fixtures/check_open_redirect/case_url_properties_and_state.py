from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


class SubmissionView:
    def post(self, request):
        return redirect(request.event.urls.base)

    def get(self, request):
        return redirect(self.object.orga_urls.base.full())

    def form_valid(self, form):
        return redirect(self.get_success_url())

    def delete(self, request):
        return redirect(request.user.profile.homepage)


def finish(request):
    url = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()}):
        return redirect("/")
    return redirect(url)


def jump(request):
    return redirect(request.session["next"])


def hop(request):
    return redirect(request.GET["url"])


def done(request, event):
    return redirect(event.orga_urls.base + "?congratulations")


def again(request, result):
    return redirect(f"{request.path}?async_id={result.id}")


def payload(request):
    form = RedirectForm()
    return redirect(form.url.data)


def short(request, code):
    submission = Submission.objects.select_related("event").get(code=code)
    return redirect(submission.urls.public)
