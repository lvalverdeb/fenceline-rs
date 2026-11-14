from django.shortcuts import redirect


def sudo(request):
    if request.method == "POST":
        return redirect(request.path)
    if request.GET.get("again"):
        return redirect(request.get_full_path())
    return redirect(request.GET["next"])
