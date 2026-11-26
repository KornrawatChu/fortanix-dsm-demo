"""Fake (but valid-looking) Thai retail-banking customers. No real data."""
import random
from datetime import date

FIRST = ["Somchai", "Suda", "Anan", "Pimchanok", "Kittipong", "Nattaya", "Wichai", "Kanokwan",
         "Thanakorn", "Siriporn", "Prasert", "Jiraporn", "Chaiwat", "Ratchanee", "Surasak", "Malee"]
LAST = ["Jaidee", "Srisuk", "Wongsawat", "Thongdee", "Rattanakul", "Boonmee", "Saetang",
        "Chaiyaporn", "Kaewmanee", "Phromma", "Sukjai", "Inthawong"]
BRANCHES = ["Phahon Yothin HQ", "Silom", "Chiang Mai", "Khon Kaen", "Hat Yai", "Phuket", "Rama 9"]


def national_id() -> str:
    d = [random.randint(1, 8)] + [random.randint(0, 9) for _ in range(11)]
    check = (11 - sum(x * (13 - i) for i, x in enumerate(d)) % 11) % 10   # Thai ID checksum
    s = "".join(map(str, d + [check]))
    return f"{s[0]}-{s[1:5]}-{s[5:10]}-{s[10:12]}-{s[12]}"


def customer() -> dict:
    acct = "".join(str(random.randint(0, 9)) for _ in range(10))
    return {
        "full_name": f"{random.choice(FIRST)} {random.choice(LAST)}",
        "national_id": national_id(),
        "account_no": f"{acct[:3]}-{acct[3]}-{acct[4:9]}-{acct[9]}",
        "phone": f"0{random.choice('689')}{random.randint(0, 9)}-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
        "branch": random.choice(BRANCHES),
    }


def applicant() -> dict:
    """A complete account-opening form (used by 'Fill sample data' and tests)."""
    c = customer()
    first, last = c["full_name"].split(" ", 1)
    dob = date(random.randint(1965, 2003), random.randint(1, 12), random.randint(1, 28))
    return {
        "title": random.choice(["Mr.", "Ms.", "Mrs."]), "first_name": first, "last_name": last,
        "national_id": c["national_id"], "date_of_birth": dob.isoformat(), "mobile": c["phone"],
        "email": f"{first.lower()}.{last.lower()}@example.com",
        "address": f"{random.randint(1, 999)}/{random.randint(1, 99)} Soi {random.randint(1, 60)}, "
                   f"{random.choice(['Phahon Yothin', 'Sukhumvit', 'Rama 9', 'Ratchada'])} Rd., Bangkok "
                   f"{random.choice(['10400', '10110', '10310', '10900'])}",
        "occupation": random.choice(["Employee", "Business owner", "Civil servant", "Freelance"]),
        "monthly_income": str(random.choice([25000, 38000, 52000, 75000, 120000])),
        "account_type": random.choice(["Savings", "Fixed Deposit"]),
    }
