from collections import defaultdict

file_path = "logs/sample.log"

fail_count = defaultdict(int)

with open(file_path, "r") as f:
    for line in f:
        parts = line.strip().split()

        event = parts[2]
        ip = parts[4].split("=")[1]

        if event == "LOGIN_FAIL":
            fail_count[ip] += 1

print("Suspicious IPs:")

for ip, count in fail_count.items():
    if count >= 3:
        print(ip, "failed logins:", count)
