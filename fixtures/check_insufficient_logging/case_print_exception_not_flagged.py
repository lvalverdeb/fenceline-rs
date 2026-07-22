for identity in identities:
    try:
        risky(identity)
    except Exception as exc:
        print(f"  SKIP {identity}: {exc}")
        continue
