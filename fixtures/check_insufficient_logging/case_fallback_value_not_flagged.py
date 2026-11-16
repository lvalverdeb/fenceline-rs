def get_filetype(name):
    try:
        return name.rsplit(".", 1)[1]
    except Exception:
        return ".jpeg"


def import_time(data):
    try:
        minutes = parse(data["prepTime"])
    except Exception:
        try:
            minutes = parse(data["cookTime"])
        except Exception:
            minutes = 0
    return minutes


def ingest(items):
    for item in items:
        try:
            store(item)
        except Exception:
            pass


def rebuild(index):
    try:
        index.rebuild()
    except Exception:
        cleanup(index)


def view(request):
    try:
        return work(request)
    except Exception:
        return render(request, "error.html")
