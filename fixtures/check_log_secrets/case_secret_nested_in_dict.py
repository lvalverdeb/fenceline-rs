from weblate.utils import messages


def create(request, form):
    token = form.save()
    messages.info(
        request,
        render_to_string("created.html", {"token": token}),
    )
    messages.info(request, render_to_string("created.html", {"count": 1}))
