import os, subprocess
from flask import request
def h():
    cmd = request.args.get("c")
    os.system("ls " + cmd)
