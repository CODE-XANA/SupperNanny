import subprocess
import json

def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.stderr}")
        return None

def insert_data_to_map():
    # Load data from data.json
    try:
        with open("data.json", "r") as json_file:
            data = json.load(json_file)

        # Extract mappings from JSON and write to /proc/super_nanny/file_list
        for app in data["applications"]:
            app_path = app["path"]
            app_name = app["name"]
            for rule in app["rules"]:
                if rule["enabled"]:
                    pattern = rule["pattern"]
                    entries = [
                        f"{app_path}:{pattern}\n",
                        f"{app_name}:{pattern}\n"
                    ]

                    for entry in entries:
                        try:
                            with open("/proc/super_nanny/file_list", "w") as proc_file:
                                proc_file.write(entry)

                            print(f"Successfully inserted: {entry.strip().split(':')[0]} -> {entry.strip().split(':')[1]}")
                        except Exception as e:
                            print(f"Error inserting data for entry: {entry.strip()}. Error: {e}")

    except FileNotFoundError:
        print("Error: data.json file not found.")
    except KeyError as e:
        print(f"Error: Missing expected key in JSON data: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Execute additional commands as per the original workflow
    commands = [
        "sudo python3 set_id.py",
        "sudo ./bpf_pass_data",
        "sudo ./read_map",
    ]

    for command in commands:
        print(f"Running command: {command}")
        output = run_command(command)
        if output:
            print(output)

if __name__ == "__main__":
    insert_data_to_map()
