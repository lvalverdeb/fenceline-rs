from fastapi.responses import JSONResponse


def page(slug):
    try:
        return render(slug)
    except Exception:
        return response_404()


def api():
    try:
        return build()
    except Exception:
        return JSONResponse({"ok": False}, status_code=500)


def view(request):
    try:
        return work(request)
    except Exception:
        return render(request, "page.html")
