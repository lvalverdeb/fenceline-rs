from pathlib import Path

key_file = Path("/tmp/supersecret.txt")
with open("/var/tmp/acme.key", "wb") as out:
    out.write(data)
shm = "/dev/shm"
for f in Path("/tmp/").glob("vulpy.apikey.*"):
    pass
safe = tempfile.NamedTemporaryFile()
doc = "temporary files live in /tmp on most systems"
