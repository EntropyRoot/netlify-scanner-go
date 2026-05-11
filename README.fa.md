<div dir="rtl">

# netlify-scanner-go

> توسعه‌دهنده: **[EntropyRoot](https://github.com/EntropyRoot)**
> 🇬🇧 برای English: **[README.md](README.md)**

اسکنر و orchestrator برای شناسایی دارایی‌هایی که پشت لبه‌ی (edge) **Netlify** قرار دارن. classifier چندسیگناله، سازنده‌ی corpus از OSINT، brute-force روی slugهای Netlify، تطبیق JARM، و TUI زنده.

> ⚠️ **فقط روی دارایی‌هایی استفاده کن که اجازه‌ی تستش رو داری.** ابزار defensive/recon.

---

## هدف پروژه

Netlify یکی از پلتفرم‌های میزبانی static + serverless پرکاربرد در دنیاست. خیلی از سایت‌های ایرانی (شخصی، استارتاپی، رسانه‌ای، پروژه‌های open-source) روی Netlify deploy شدن، و بخش زیادی از این سایت‌ها از داخل ایران **به‌خاطر فیلترینگ ISP یا تحریم Netlify** قابل دسترس نیستن — یا SNI بلاک شده، یا IP بلاک شده، یا هر دو.

این پروژه دو هدف داره:

1. **شناسایی منظم دارایی‌های پشت Netlify** — برای تیم‌های امنیتی، researcherها، asset inventory و recon.
2. **پیدا کردن مسیرهای دور زدن سانسور برای رسیدن به Netlify** — مخصوصاً از داخل ایران. این یعنی پیدا کردن SNIهای باز، IPهای edge که هنوز فیلتر نشدن، و جفت کردنشون با هم تا یک مسیر زنده ساخته بشه. این کار ضد‌سانسوره: اگر سایت X پشت Netlify باشه و Netlify از داخل ایران بلاک باشه، خروجی این ابزار می‌تونه به ابزارهای دیگه (مثل [SNI Spoofing](https://github.com/patterniha) یا proxyهای SNI-aware) feed بشه تا با SNI/IP درست، دسترسی به سایت برقرار بشه.

> پروژه هیچ proxyای فعال نمی‌کنه، هیچ ترافیکی tunnel نمی‌کنه. فقط **scan و گزارش** می‌ده. استفاده از خروجیش برای ابزارهای دیگه به عهده‌ی کاربره.

---

## حالت Iran چی کار می‌کنه؟

`netlify-scanner-go iran` — یک workflow کاملاً **stdlib-only** (بدون نیاز به subfinder/dnsx/httpx/naabu/nuclei) که از داخل شبکه‌های فیلترشده اجرا میشه و سه مرحله داره:

1. **probe کردن SNIهای seed.** ~۵۴۰ SNI رو (که embed شدن تو binary) با TLS handshake واقعی تست می‌کنه. هرکدوم که handshake موفق + cert نتلیفای داد → `open`. IPهاش رو نگه می‌داره برای مرحله ۲.
2. **probe کردن IPهای candidate روی پورت ۴۴۳.** هم seed IPها، هم CIDR رنج‌هایی که خودت می‌دی (`--cidr 199.36.158.0/23`)، هم لیست کاستوم (`--ips file.txt`). برای هر IP که TCP+TLS موفق شد، cert peer رو می‌خونه و SAN رو ثبت می‌کنه.
3. **re-probe کردن SANهای کشف‌شده.** برای هر hostname نتلیفای که از مرحله ۲ پیدا شد، چک می‌کنه آیا اون hostname هم از همین شبکه قابل دسترسه یا نه.

خروجی نهایی JSON با این فیلدها:

```json
{
  "open_snis":      ["app.netlify.com", "..."],
  "open_ips":       ["75.2.60.5", "..."],
  "harvested_snis": ["foo.netlify.app", "..."],
  "usable_pairs": [
    {"sni": "app.netlify.com", "ip": "75.2.60.5"}
  ]
}
```

`usable_pairs` مهم‌ترین قسمته — این یعنی **(SNI، IP)**هایی که هر دو از این شبکه پاسخ دادن. این جفت‌ها مستقیماً قابل feed به ابزارهای SNI-spoofing هستن.

---

## نصب

```bash
go install github.com/EntropyRoot/netlify-scanner-go@latest
```

یا build از source:

```bash
git clone https://github.com/EntropyRoot/netlify-scanner-go
cd netlify-scanner-go
make build
```

برای `scan`/`quick` باید ابزارهای ProjectDiscovery هم نصب باشن — اولین بار خودش دانلود می‌کنه (با `go install`). برای `iran` و `slug` و `verify` و `iran` **هیچ ابزار خارجی لازم نیست**.

---

## نمونه‌های سریع

```bash
# اسکن کامل با TUI
netlify-scanner-go scan -t example.com

# Iran mode با seedهای پیش‌فرض
netlify-scanner-go iran -o iran-report.json

# Iran mode با CIDR رنج‌های نتلیفای (وقتی BGPView فیلتر باشه)
netlify-scanner-go iran \
  --cidr 199.36.158.0/23 \
  --cidr 75.2.60.0/24 \
  --workers 256 --timeout 3s -o iran.json

# اسکن کامل CIDR + extras + cap
netlify-scanner-go iran \
  --cidrs ranges.txt \
  --ips extras.txt \
  --max-ips 50000 -o full.json

# Verify یک لیست IP که از قبل داری (پاک کردن نویز)
netlify-scanner-go verify --ips old-list.txt -o clean.json

# Brute-force روی slugها
netlify-scanner-go slug --wordlist top-10k.txt --only-live -o live.txt

# JARM یاد بگیر
netlify-scanner-go jarm --learn --ips netlify-ips.txt
```

---

## subcommandها

| دستور      | کارش                                                                  |
| ---------- | --------------------------------------------------------------------- |
| `scan`     | pipeline کامل با TUI                                                  |
| `quick`    | اجرای یک‌بارجا: harvest + ASN + SNI + iterative + pipeline           |
| `check`    | فینگرپرینت یک یا چند host (JARM اگر tlsx نصب باشه)                    |
| `verify`   | تأیید cert/SAN + `x-nf-request-id` برای IP/SNI                        |
| `discover` | ساخت IP allow-set نتلیفای (seed + ASN + SNI [+ harvest])              |
| `harvest`  | کشیدن hostname نتلیفای از ۷ منبع OSINT                                |
| `slug`     | brute-force روی `<slug>.netlify.app` (wildcard-safe)                  |
| `jarm`     | یادگیری / چک JARM (با tlsx)                                           |
| **`iran`** | **workflow ایرانی، stdlib-only**                                       |
| `diff`     | مقایسه دو خروجی JSONL                                                 |
| `replay`   | پخش session ضبط‌شده توی TUI (بدون شبکه)                              |
| `sni`      | چاپ corpus SNI embed شده                                              |
| `install`  | نصب/آپدیت ابزارهای خارجی                                              |

---

## scoring (آستانه = ۳۰ → Netlify)

| سیگنال                              | امتیاز |
| ----------------------------------- | -----: |
| `x-nf-request-id` (یا هر `x-nf-*`)  |    +۶۰ |
| CNAME پسوند نتلیفای                 |    +۵۰ |
| `A == 75.2.60.5` (apex fallback)    |    +۵۰ |
| IP ∈ AS54113                        |    +۳۰ |
| JARM match با hash شناخته‌شده       |    +۲۵ |
| `Server: Netlify`                   |    +۲۵ |
| TLS SAN match با پسوند نتلیفای      |    +۲۰ |

---

## کلیدهای TUI

| کلید                | کار                                       |
| ------------------- | ----------------------------------------- |
| `1`–`5`             | تعویض تب                                  |
| `tab` / `shift+tab` | چرخش تب‌ها                                |
| `/`                 | فیلتر روی تب فعال (`esc` پاک می‌کنه)     |
| `j`/`k`  `↑`/`↓`    | اسکرول                                    |
| `pgup` / `pgdown`   | نصف صفحه                                  |
| `g` / `G`           | بالا / پایین                              |
| **`+` / `-`**       | **تنظیم زنده‌ی rate naabu (±۱۰۰ pps)**    |
| **`]` / `[`**       | **تنظیم زنده‌ی rate naabu (±۱۰۰۰ pps)**   |
| `?`                 | کمک                                       |
| `q` / `ctrl+c`      | خروج                                      |

---

## نکته‌ی مهم در مورد نویز seed list


این نسخه:
- `verify` رو به‌عنوان مرحله‌ی مستقل اضافه کرده — قبل از اعتماد به هر IP، با TLS handshake و چک cert SAN تأیید می‌کنه.
- در `--aggressive` به‌صورت پیش‌فرض `StrictSAN=true` هست — هر cert غیرنتلیفای دور انداخته میشه.
- در `slug` به‌جای DNS lookup (که به‌خاطر wildcard DNS هرچیزی رو live می‌کرد)، HTTP HEAD می‌زنه و status ۴۰۴ رو تشخیص میده.

---

## مشارکت و گزارش باگ

از [github.com/EntropyRoot/netlify-scanner-go](https://github.com/EntropyRoot/netlify-scanner-go) issue باز کن یا PR بفرست. خوش‌حال می‌شم.

## لایسنس

[MIT](LICENSE) — کاملاً free / open-source.

</div>
