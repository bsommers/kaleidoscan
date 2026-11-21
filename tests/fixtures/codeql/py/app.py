import os
from flask import request


def h():
    os.system("ls " + request.args.get("c"))
