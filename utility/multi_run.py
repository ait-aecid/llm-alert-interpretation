import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser(
        description="Run another Python script multiple times."
    )
    parser.add_argument(
        "script",
        help="Path to the Python script to run."
    )
    parser.add_argument(
        "-n", "--num_runs",
        type=int,
        default=10,
        help="Number of times to run the script."
    )

    args = parser.parse_args()

    for i in range(args.num_runs):
        print(f"Running iteration {i + 1}/{args.num_runs}...")
        result = subprocess.run(["python", args.script])

        if result.returncode != 0:
            print(f"Script failed on iteration {i + 1} (exit code {result.returncode}). Stopping.")
            break

        print(f"Iteration {i + 1} completed.\n")

if __name__ == "__main__":
    main()