import shutil
import sys

UPLOADS = "/srv/uploads"


def save(upload, name):
    shutil.move(upload, UPLOADS + "/" + name)


def main():
    shutil.copy(sys.argv[1], sys.argv[2])


def rotate():
    shutil.move(UPLOADS + "/current", UPLOADS + "/previous")
