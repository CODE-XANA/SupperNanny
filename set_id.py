import subprocess
import re

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr.decode('utf-8')}")
        return None

def get_map_id(map_name):
    command = "sudo bpftool map show"
    output = run_command(command)
    if output:
        match = re.search(r"(\d+):\s+hash\s+name\s+" + re.escape(map_name) + r"\s+flags", output)
        if match:
            print("Matched id is : ", match.group(1))
            return match.group(1)  
    return None

def pin_bpf_map(map_name, pin_path):
    map_id = get_map_id(map_name)
    if map_id:
        command = f"sudo bpftool map pin id {map_id} {pin_path}"
        result = run_command(command)
        if result:
            print(f"Map '{map_name}' (ID {map_id}) pinned to {pin_path}")
    else:
        print(f"Map '{map_name}' not found")

if __name__ == "__main__":
    map_name = "app_file_map"
    pin_path = "/sys/fs/bpf/app_file_map"
    pin_bpf_map(map_name, pin_path)
