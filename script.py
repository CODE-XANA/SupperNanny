import os
import random
import string
import subprocess

subprocess.run(["make", "clean"], check=True)
subprocess.run(["make"], check=True)
subprocess.run(["sudo", "rmmod", "supernanny_module"], check=False)
subprocess.run(["sudo", "insmod", "supernanny_module.ko"], check=True)


print("**********************************BUILDING FILTER**********************************")
subprocess.run(["./ecc", "file_filter.bpf.c"], check=True)


print("**********************************RUNNING FILTER**********************************")
subprocess.run(["sudo", "./ecli", "run", "package.json"], check=True)
map_path = "/sys/fs/bpf/app_file_map"
subprocess.run(["sudo", "rm", map_path], check=True)
print("Script Over")
