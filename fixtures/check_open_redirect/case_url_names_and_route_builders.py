from django.shortcuts import redirect
from django.urls import reverse
from flask import request, url_for


def django_views(request, code):
    redirect("hc-checks", code)
    redirect("admin:auth_user_delete", request.GET["id"])
    return redirect(reverse("hc-details", args=[code]))


def flask_views(topic_id):
    topic = Topic.query.filter_by(id=topic_id).first_or_404()
    redirect(url_for("forum.topic", topic_id=request.args["t"]))
    redirect(topic.url)
    return redirect(request.args["next"])
