# Demo Script — Horizon Bank × Fortanix DSM (30–45 นาที)

## การจัดหน้าจอ
```
┌──────────────────────────┬──────────────────────────────┐
│ Browser                  │ VS Code (เปิดโฟลเดอร์ DSM-Demo)│
│  tab 1: localhost:5000   │  - config.yaml                 │
│  tab 2: localhost:5000/staff                              │
│  tab 3: DSM UI (apac)    ├──────────────────────────────┤
│                          │ Terminal (ใน VS Code)          │
│                          │  python reencrypt_job.py       │
└──────────────────────────┴──────────────────────────────┘
        + DBeaver (PostgreSQL horizon_bank) เปิดไว้อีกหน้าต่าง
```

**ก่อนลูกค้าเข้าห้อง (10 นาที)**
1. เปิด **Docker Desktop** (รอจนขึ้น Engine running)
2. Reset ข้อมูล: `docker compose down -v` → `docker compose up -d` และลบไฟล์ `config.yaml` (จะถูกสร้างใหม่เป็น AES-128 / CBC)
3. รัน `tests\smoke_test.py rest` แล้วต้องจบด้วย `ALL ROUND-TRIPS OK`
4. รัน `python bank_app.py` แล้วเปิด tab ทั้ง 3 ให้พร้อม
5. ใน VS Code เปิด `config.yaml` ทิ้งไว้ และกด Ctrl+Shift+F ค้นหา `[DSM-INTEGRATION` เตรียมไว้
6. DBeaver: connect ไปที่ `horizon_bank` (ดู README) แล้วเปิด SQL Editor เตรียม query ไว้

---

## ① แอปของลูกค้า "ธรรมดาที่สุด" (5 นาที)
- เปิด `localhost:5000` แล้วพูดว่า **"นี่คือแอปเปิดบัญชีแบบที่ธนาคารมีอยู่แล้ว"**
- กด **Fill sample data** แล้วกด **Submit** จะได้ Reference number
- Message: **ผู้ใช้ไม่รู้เลยว่ามี encryption และ UX ไม่เปลี่ยน**

## ② ข้อมูลใน Database (5 นาที) — Security / Compliance
- ไป tab `/staff`: คอลัมน์ **National ID as stored** เป็น ciphertext และคอลัมน์ **Protected by** บอก algorithm กับ key
- กด **Open →** ซ้ายคือข้อมูลที่พนักงานที่มีสิทธิ์เห็น (decrypt ผ่าน DSM) ขวาคือค่าที่อยู่ใน DB จริง
- ชี้ `kid` และ `mode` ใน JSON: **"ทุก field บอกได้ว่าถูก encrypt ด้วย key version ไหน"**
- **หลักฐานจาก database จริง:** สลับไป **DBeaver** แล้วรัน
  ```sql
  SELECT ref_no, first_name, last_name, national_id, mobile, monthly_income FROM account_applications;
  ```
  - "นี่คือ PostgreSQL ตัวจริง เครื่องมือของ DBA ไม่ผ่านแอปของเรา"
  - `first_name` อ่านออก แต่ `national_id` / `mobile` / `monthly_income` เป็น ciphertext → **DBA, backup หรือ attacker ที่เข้า DB ได้ก็อ่าน PII ไม่ได้**
  - ต่างจาก TDE ตรงที่ TDE ป้องกันไฟล์บนดิสก์ แต่ใครที่ query ผ่าน SQL ได้ยังเห็นข้อมูลจริง

## ③ จุดเชื่อมต่อกับ DSM อยู่ตรงไหน (8 นาที) — Dev
ใน VS Code กด **Ctrl+Shift+F → `[DSM-INTEGRATION`** จะเห็นทุกจุดในหน้าเดียว:

| Banner | ไฟล์ | พูดว่า |
|---|---|---|
| `0/3 CONNECT` | `bank_app.py` | สร้าง client ครั้งเดียว โดย endpoint และ key มาจาก `.env` |
| `1/3 AUTHENTICATE` | `dsm/rest_client.py` | App API key แลกเป็น token อายุสั้น |
| `2/3 ENCRYPT` | `dsm/rest_client.py` | เรียกด้วย **key name** และ `mode` เป็น parameter |
| `3/3 DECRYPT` | `dsm/rest_client.py` | เรียกด้วย **kid** ที่เก็บไว้กับข้อมูล |

แล้วค้นหา `[DSM-POLICY]` ต่อ:
- `crypto_service.py`: business code เรียกแค่ `protect()` / `reveal()`
- `account_repository.py`: โค้ดธุรกิจมีแค่ `enc.protect(...)` **ไม่มี algorithm ไม่มี key**
- (Option) เปิด `dsm/sdk_client.py` เทียบให้ดูว่า SDK ก็คือ 3 จุดเดิม

## ④ เปลี่ยน Algorithm แบบสดๆ (12 นาที) — ไฮไลต์
**A · CBC → GCM**
1. ใน VS Code `config.yaml` แก้ `mode: CBC` เป็น `mode: GCM` แล้วกด **Save** (ไม่ต้อง restart)
2. ไป tab 1 แล้ว Submit ฟอร์มใหม่
3. ไป `/staff` จะเห็นรายการใหม่เป็น **DSM AES (GCM)** ส่วนรายการเก่ายังเป็น **CBC** และทั้งคู่เปิดอ่านได้
4. Terminal: `python reencrypt_job.py` จะแสดง Before/After ว่าทุกค่ากลายเป็น GCM
5. Refresh `/staff` จะเห็นว่าเป็น GCM ทั้งหมด

**B · AES-128 → AES-256**
- แก้ `key_name: kbtg-demo-aes128` เป็น `kbtg-demo-aes256` แล้ว Save → Submit → `reencrypt_job.py`
- ไป DSM UI → Security Objects → เปิด `kbtg-demo-aes256` ให้เห็นว่าเป็น 256 bits และ **ไม่มีสิทธิ์ Export**

**C · Key rotation (ไม่แตะแอปเลย)**
- ใน DSM UI เปิด `kbtg-demo-aes256` แล้วกด **Rotate key**
- กลับมา Submit ฟอร์ม → `/staff` จะเห็น kid ใหม่ ทั้งที่ **config และ code ไม่เปลี่ยน**
- `reencrypt_job.py` เพื่อย้ายข้อมูลเก่ามาใช้ version ใหม่

**E · เปลี่ยนจาก RSA เป็น AES โดยใช้ชื่อ key เดิม (ไม่แตะแอป)**
- เตรียม: `config.yaml` ตั้ง `key_name: kbtg-demo-data-key` (สมมติว่าระบบเดิมของลูกค้าใช้ RSA) แล้ว Submit 1 ครั้ง → `/staff` แสดง **DSM RSA (OAEP)**
- ใน DSM UI → Security Objects → `kbtg-demo-data-key` (RSA-2048):
  1. เปลี่ยนชื่อเป็น `kbtg-demo-data-key (RSA retired)`
  2. **Add Security Object** → AES, 256 bits, ตั้งชื่อ `kbtg-demo-data-key`, Group `KBTG-Demo`, เปิด Encrypt/Decrypt
  - (ถ้าไม่อยากคลิกเอง: `python swap_key_type.py` ทำ 2 ขั้นนี้ให้)
- Submit ฟอร์มอีกครั้ง → รายการใหม่เป็น **DSM AES (GCM)** ส่วนรายการ RSA เก่ายังกด Open อ่านได้
- Message: **"การเปลี่ยนประเภท key เป็น policy ใน DSM ทีม Security ทำได้เองโดยไม่ต้องรอทีม Dev"**
- ทำไมต้องย้ายจาก RSA? RSA-2048 encrypt ได้ไม่เกิน 190 bytes ต่อครั้ง และช้ากว่า AES มาก
- ถ้าเป็นแบบ "rotate" จะทำไม่ได้: DSM ตอบ `cannot rekey into a new object type` ต้องใช้การสร้าง key ใหม่ภายใต้ชื่อเดิมแทน
- `python reencrypt_job.py` เพื่อย้ายข้อมูล RSA เก่าไปเป็น AES
- ซ้อมซ้ำ: `python swap_key_type.py kbtg-demo-data-key RSA` จะสลับกลับเป็น RSA

**F · Re-encryption แบบ online + หยุดแล้วทำต่อได้** (ประมาณ 4 นาที, ใช้ต่อจากฉาก A ได้)
- เตรียมก่อนเดโม: `python seed_data.py 100` ตอน config ยังเป็น CBC (ใช้เวลาประมาณ 45 วินาที)
- แก้ `mode: GCM` → รัน `python reencrypt_job.py` (100 แถวใช้เวลาประมาณ 65 วินาที)
- ระหว่างที่ progress bar วิ่ง → Submit ฟอร์ม 1 รายการ → **ใช้งานได้ปกติ**
- กด **Ctrl+C** → `STOPPED … nothing half-written`
- DBeaver query สรุป → เห็น CBC กับ GCM อยู่ร่วมกัน → เปิด `/staff` ดูได้ทั้งสองแบบ
- รัน `reencrypt_job.py` อีกครั้ง → ทำต่อจากที่ค้าง (`already on the current policy`) → GCM ทั้งหมด

**D · ถ้าเป็นแบบ hardcode ล่ะ?**
- เปิด `legacy_hardcoded.py` แล้วค้นหา `!ALGO` จะเจอ **13 จุดใน 4 ที่** ที่ต้องแก้ ไม่มี kid ให้รู้ว่าข้อมูลเป็นแบบเก่าหรือใหม่ และ key อยู่บน server
- เทียบกับที่เพิ่งทำไป: **1 บรรทัดใน config.yaml**

## ⑤ Audit (5 นาที) — Compliance
- DSM UI → **Audit Log**: จะเห็นว่า `App "kbtg-demo-app" used key … to perform "Encryption"`, การ rotate และเวลาที่เกิดขึ้น
- Message: **ทุกการใช้ key มีหลักฐานอยู่ที่เดียว แยกจากแอป**

## ปิด — Q&A
**สรุป 3 ข้อ:** (1) แอปเชื่อมกับ DSM แค่ 3 จุด หาได้ด้วยการค้นหาคำเดียว (2) เปลี่ยน algorithm = แก้ config 1 บรรทัด + re-encrypt แบบ online (3) key อยู่ใน HSM ทุกการใช้งานมี audit

| คำถามที่น่าจะเจอ | คำตอบ |
|---|---|
| Latency? | ประมาณ 50–60 ms ต่อ call ไป DSM SaaS apac จากกรุงเทพฯ ถ้าเป็น on-prem หรือใช้ Envelope จะลดลงได้อีก (โชว์ได้ใน `console_app.py`) |
| DSM ล่ม? | DSM เป็น cluster HA และ Envelope + DEK cache ช่วยลด dependency |
| ข้อมูลส่งขึ้น cloud ไหม? | Direct = ใช่ (ผ่าน TLS) ถ้าไม่ต้องการ ใช้ Envelope หรือ DSM on-prem |
| Search บนคอลัมน์ที่ encrypt? | ใช้ tokenization/FPE หรือ blind index |
| ภาษาอื่น? | REST เหมือนกันทุกภาษา และมี SDK / JCE / PKCS#11 ให้ด้วย |

**สำรอง DB:** ถ้า Docker มีปัญหา ใส่ `#` หน้า `DATABASE_URL` ใน `.env` แอปจะกลับไปใช้ SQLite (`data\bank.db`) ซึ่ง DBeaver ก็เปิดได้เหมือนกัน

**สำรอง:** ถ้าเน็ตใช้ไม่ได้ ให้ตั้ง `DSM_BACKEND=mock` ใน `.env` แล้ว restart และถ้าลูกค้าอยากเจาะลึก (benchmark Direct vs Envelope, key inventory) ให้เปิด `streamlit run console_app.py`
