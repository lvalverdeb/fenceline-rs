for _ in range(3):
    try:
        risky()
    except ValueError:
        continue
