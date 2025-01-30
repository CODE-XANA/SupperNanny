import subprocess

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
    # Open the input file
    with open("input_files.txt", "r") as f:
        mappings = [line.strip().split(":") for line in f if ":" in line]

        # Write mappings to /proc/super_nanny/file_list
        for process, file_path in mappings:
            try:
                # Create the entry as "process:file_path"
                entry = f"{process}:{file_path}\n"

                # Write directly to the /proc interface
                with open("/proc/super_nanny/file_list", "w") as proc_file:
                    proc_file.write(entry)

                print(f"Successfully inserted: {process} -> {file_path}")
            except Exception as e:
                print(f"Error inserting data for process: {process}, file: {file_path}. Error: {e}")

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
