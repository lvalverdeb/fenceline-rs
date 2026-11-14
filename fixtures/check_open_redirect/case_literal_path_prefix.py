from django.shortcuts import redirect


def task_detail(request, project_id, task_id):
    return redirect('/taskManager/' + project_id + '/' + task_id)


def next_page(request):
    target = request.GET.get("next", "")
    redirect(f"/account/{target}")
    redirect("/account/%s" % target)
    redirect("/account/{}".format(target))
    redirect("/" + target)
    redirect("//" + target)
    redirect("\\" + target)
    redirect(target + "/account/")
    return redirect("https://" + target)
