#!/usr/bin/env python3
"""
record-trajectory.py — Commits a code-mode execution run to the trajectory repository.
Inspired by smithclay/codemode-git.
"""
import os, sys, subprocess, time, json

TRAJECTORY_REPO = r"C:\Users\AMMAR\Hermes Agents\Projects\code-mode-trajectories"

def record_run(task_name, script_content, result_output, status="completed"):
    if not os.path.exists(TRAJECTORY_REPO):
        os.makedirs(TRAJECTORY_REPO, exist_ok=True)
        subprocess.run(["git", "init"], cwd=TRAJECTORY_REPO, check=True)

    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    run_dir = os.path.join(TRAJECTORY_REPO, "runs", f"{timestamp}_{task_name}")
    os.makedirs(run_dir, exist_ok=True)

    with open(os.path.join(run_dir, "run.py"), "w", encoding="utf-8") as f:
        f.write(script_content)

    with open(os.path.join(run_dir, "output.log"), "w", encoding="utf-8") as f:
        f.write(result_output)

    meta = {
        "timestamp": timestamp,
        "task": task_name,
        "status": status
    }
    with open(os.path.join(run_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    subprocess.run(["git", "add", "."], cwd=TRAJECTORY_REPO, check=True)
    msg = f"trajectory({task_name}): {status} at {timestamp}"
    subprocess.run(["git", "commit", "-m", msg], cwd=TRAJECTORY_REPO, check=True)
    print(f"Recorded trajectory commit: {msg}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: record-trajectory.py <task_name> <script_path> [status]")
        sys.exit(1)
    t_name = sys.argv[1]
    s_path = sys.argv[2]
    stat = sys.argv[3] if len(sys.argv) > 3 else "completed"
    with open(s_path, "r", encoding="utf-8") as sf:
        s_code = sf.read()
    record_run(t_name, s_code, "Execution recorded via CLI", stat)
