import os

# Define test cases
TEST_CASES = [
    {
        "description": "Blocked file access",
        "file_path": "/tmp/one.txt",
        "expected_result": "blocked",  # The file is blocked by BPF
    },
    {
        "description": "Blocked file access",
        "file_path": "/home/user/Downloads/test.txt",
        "expected_result": "blocked",  # The file is blocked by BPF
    },
    {
        "description": "Allowed file access",
        "file_path": "/home/user/Documents/master_project/f_pr-main/input.txt",
        "expected_result": "allowed",  # The file should be accessible
    },
    {
        "description": "Non-existent file access",
        "file_path": "/tmp/four.txt",
        "expected_result": "nonexistent",  # File doesn't exist, unrelated to BPF
    },
]

def run_test_case(test_case):
    file_path = test_case["file_path"]
    expected_result = test_case["expected_result"]
    description = test_case["description"]

    print(f"Running test: {description}")

    try:
        with open(file_path, "r") as f:
            content = f.read()
            if expected_result == "blocked":
                print(f"FAIL: File {file_path} should be blocked but was accessed.")
            else:
                print(f"PASS: File {file_path} was accessed as expected.")
    except FileNotFoundError:
        if expected_result == "nonexistent":
            print(f"PASS: File {file_path} correctly identified as non-existent.")
        else:
            print(f"FAIL: File {file_path} should exist but was not found.")
    except PermissionError:
        if expected_result == "blocked":
            print(f"PASS: File {file_path} correctly blocked by BPF.")
        else:
            print(f"FAIL: File {file_path} should not be blocked but was denied access.")
    except Exception as e:
        print(f"FAIL: Unexpected error for file {file_path}: {e}")


if __name__ == "__main__":
    for case in TEST_CASES:
        run_test_case(case)
