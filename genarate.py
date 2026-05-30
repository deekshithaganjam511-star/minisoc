import pandas as pd
import random
from faker import Faker
from datetime import datetime, timedelta

fake = Faker()

# --- Config ---
NUM_LOGS = 500
OUTPUT_FILE = "data/logs.csv"

# --- Data Pools ---
USERS = ["admin", "john.doe", "jane.smith", "root", "deekshitha", "guest", "hr.user", "dev.ops"]
ATTACK_IPS = ["185.220.101.45", "45.33.32.156", "103.21.244.0", "198.51.100.23", "192.0.2.77"]
COUNTRIES = ["US", "IN", "RU", "CN", "BR", "DE", "NG", "KP"]
ATTACK_COUNTRIES = ["RU", "CN", "KP", "NG"]

def random_timestamp(attack=False):
    base = datetime.now() - timedelta(days=1)
    if attack:
        # After-hours: between 12am - 5am
        hour = random.randint(0, 4)
    else:
        # Business hours: 9am - 6pm
        hour = random.randint(9, 18)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second).strftime("%Y-%m-%d %H:%M:%S")

def generate_normal_log():
    return {
        "timestamp": random_timestamp(attack=False),
        "user": random.choice(USERS),
        "ip": fake.ipv4(),
        "country": random.choice(["US", "IN", "DE", "BR"]),
        "status": "SUCCESS",
        "attempt_count": 1,
        "event_type": "normal_login"
    }

def generate_brute_force_log():
    ip = random.choice(ATTACK_IPS)
    user = random.choice(USERS)
    logs = []
    for i in range(random.randint(8, 15)):
        logs.append({
            "timestamp": random_timestamp(attack=True),
            "user": user,
            "ip": ip,
            "country": random.choice(ATTACK_COUNTRIES),
            "status": "FAILED",
            "attempt_count": i + 1,
            "event_type": "brute_force"
        })
    return logs

def generate_after_hours_log():
    return {
        "timestamp": random_timestamp(attack=True),
        "user": random.choice(USERS),
        "ip": fake.ipv4(),
        "country": random.choice(COUNTRIES),
        "status": "SUCCESS",
        "attempt_count": 1,
        "event_type": "after_hours_login"
    }

def generate_credential_stuffing_log():
    ip = random.choice(ATTACK_IPS)
    logs = []
    for _ in range(random.randint(5, 10)):
        logs.append({
            "timestamp": random_timestamp(attack=True),
            "user": random.choice(USERS),
            "ip": ip,
            "country": random.choice(ATTACK_COUNTRIES),
            "status": "FAILED",
            "attempt_count": 1,
            "event_type": "credential_stuffing"
        })
    return logs

# --- Main Generator ---
all_logs = []

for _ in range(NUM_LOGS):
    roll = random.random()
    if roll < 0.65:
        all_logs.append(generate_normal_log())
    elif roll < 0.80:
        all_logs.extend(generate_brute_force_log())
    elif roll < 0.90:
        all_logs.append(generate_after_hours_log())
    else:
        all_logs.extend(generate_credential_stuffing_log())

# --- Save to CSV ---
df = pd.DataFrame(all_logs)
df = df.sort_values("timestamp").reset_index(drop=True)
df.to_csv(OUTPUT_FILE, index=False)

print(f"Generated {len(df)} log entries → saved to {OUTPUT_FILE}")
print(df["event_type"].value_counts())