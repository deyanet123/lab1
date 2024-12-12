import re
import json
import csv
# Log məlumatları
logs = """192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] \"POST /login HTTP/1.1\" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] \"POST /login HTTP/1.1\" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] \"POST /login HTTP/1.1\" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] \"POST /login HTTP/1.1\" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] \"POST /login HTTP/1.1\" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] \"POST /login HTTP/1.1\" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] \"GET /home HTTP/1.1\" 200 3020"""

# Regex ifadəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(POST|GET|PUT|DELETE|PATCH|OPTIONS)"

# Uyğunluqları tap
matches = re.findall(pattern, logs)

# Nəticələri göstər
for match in matches:
    ip_address, date, http_method = match
    print(f"IP Ünvanı: {ip_address}, Tarix: {date}, HTTP Metodu: {http_method}")



# Regex ifadəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] \"POST /login HTTP/1.1\" 401"

# Uğuruzsuz cəhdi olan IP-ləri tapın
failed_attempts = re.findall(pattern, logs)

# Hər IP-ni sayın
failed_attempts_count = {}
for ip in failed_attempts:
    failed_attempts_count[ip] = failed_attempts_count.get(ip, 0) + 1

# 5-dən çox cəhdi olan IP-ləri saxlayın
suspicious_ips = {ip: count for ip, count in failed_attempts_count.items() if count > 5}

# JSON faylına yazın
with open("suspicious_ips.json", "w") as json_file:
    json.dump(suspicious_ips, json_file, indent=4)

print("Uğurusuz cəhd sayı 5-dən çox olan IP-lər JSON faylına yazıldı.")

# Regex ifadəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] \"POST /login HTTP/1.1\" 401"


# Regex ifadəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] \"POST /login HTTP/1.1\" 401"

# Uğursuz giriş cəhdlərini tapın
failed_attempts = re.findall(pattern, logs)

# Hər bir IP ünvanı üçün uğursuz giriş sayını hesablayın
failed_attempts_count = {}
for ip in failed_attempts:
    failed_attempts_count[ip] = failed_attempts_count.get(ip, 0) + 1

# Məlumatları mətn faylına yazın
with open("failed_attempts.txt", "w") as text_file:
    for ip, count in failed_attempts_count.items():
        text_file.write(f"IP: {ip}, Failed Attempts: {count}\n")

print("Bütün uğursuz giriş cəhdləri mətn faylına yazıldı.")

# Regex ifadəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(POST|GET|PUT|DELETE) .*?\" (\d+)"

# Məlumatları saxlamaq üçün siyahı
log_data = []

# Regex ilə məlumatları çıxarın
for match in re.finditer(pattern, logs):
    ip = match.group(1)
    date = match.group(2)
    method = match.group(3)
    status_code = match.group(4)

    if status_code == "401":  # Yalnız uğursuz cəhdlər
        log_data.append({
            "IP": ip,
            "Date": date,
            "HTTP Method": method,
            "Failed Attempts": 1
        })

# Hər IP üzrə uğursuz cəhdləri toplamaq
aggregated_data = {}
for entry in log_data:
    ip = entry["IP"]
    if ip not in aggregated_data:
        aggregated_data[ip] = {"Date": entry["Date"], "HTTP Method": entry["HTTP Method"], "Failed Attempts": 0}
    aggregated_data[ip]["Failed Attempts"] += entry["Failed Attempts"]

# CSV faylına yazın
with open("failed_attempts.csv", "w", newline="") as csvfile:
    fieldnames = ["IP", "Date", "HTTP Method", "Failed Attempts"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for ip, data in aggregated_data.items():
        writer.writerow({"IP": ip, "Date": data["Date"], "HTTP Method": data["HTTP Method"],
                         "Failed Attempts": data["Failed Attempts"]})

print("Uğursuz giriş cəhdləri CSV faylına yazıldı.")
