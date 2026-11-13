def handler(request):
    data = request.body.read()
    head = request.body.read(1024)
    body = stream.read()
