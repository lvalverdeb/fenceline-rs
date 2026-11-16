import traceback

try:
    configure()
except Exception:
    traceback.print_exc()

try:
    configure()
except Exception:
    cleanup()
