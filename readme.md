# Mohtavanegar Antivirus

پلاگین آنتی‌ویروس وردپرس برای پاکسازی سایت‌های آلوده.

## قابلیت‌ها

### ۱) اسکن (Scan)
- اسکن `wp-content`، هسته وردپرس، و تمام فایل‌های `.htaccess`
- تشخیص کدهای تزریق‌شده (eval/base64، webshell، iframe مخفی، JS مبهم و ...)
- تشخیص ویروس جدید: ساخت `.htaccess` جعلی در تک‌تک پوشه‌ها
- تشخیص PHP داخل پوشه `uploads`
- تشخیص خانواده `xdav-tracker` / پلاگین‌های مخفی و ادمین ghost

### ۲) رفع (Fix)
- پاک کردن تکه کد تزریق‌شده از فایل‌های سالم (بدون حذف کل فایل)
- حذف `.htaccess` های جعلی
- حذف فایل‌های مخرب (بعد از قرنطینه)

### ۳) تعمیر (Repair)
- جایگزینی فایل‌های هسته از `sources/wordpress_core.zip`
- بازیابی `.htaccess` ریشه از `sources/default.htaccess`
- **پاک‌سازی پایدار xdav-tracker / Zonal Runner Tap** (شکستن auto-prepend، حذف dropper/cron/IoC و scrub دیتابیس)
- **جایگزینی پلاگین‌های مخزن وردپرس** (Elementor، Classic Editor، LiteSpeed Cache و ...) از wordpress.org
- اصلاح سطح دسترسی‌ها (755/644/600)

### ۴) سخت‌سازی (Hardening)
- مسدودسازی XML-RPC
- محافظت Brute Force روی صفحه ورود
- غیرفعال‌سازی ویرایشگر فایل
- مخفی‌سازی نسخه وردپرس
- جلوگیری از User Enumeration
- هدرهای امنیتی پایه

## نصب

1. پوشه `mohtavanegar-antivirus` را در `wp-content/plugins/` کپی کنید.
2. مطمئن شوید این دو فایل داخل پلاگین هستند:
   - `sources/wordpress_core.zip`
   - `sources/default.htaccess`
3. از پیشخوان وردپرس پلاگین را فعال کنید.
4. منوی **آنتی‌ویروس** را باز کنید.

## ترتیب پیشنهادی بعد از آلودگی

1. در Repair → حذف فوری IoCهای xdav / security-helper (قبل از تکیه به داشبورد وردپرس)
2. اسکن کامل (فایل + DB + پلاگین مخفی)
3. رفع مشکلات (حذف injection + htaccess جعلی + قرنطینه)
4. حذف ادمین ghost از دیتابیس (بعد از حذف کد مخفی‌کننده)
5. تعمیر هسته از zip + deny-PHP روی uploads
6. بازیابی htaccess ریشه + اصلاح Permissions
7. فعال‌سازی سخت‌سازی + عوض کردن همه پسوردها/FTP و saltهای wp-config

## پاک‌سازی اضطراری Zonal / xdav

اگر فایل‌های `.user.ini`، hex PHP، `db.php` یا `mu-plugins/zonal-runner-tap.php` بلافاصله برمی‌گردند، زنجیرهٔ
`auto_prepend_file` قبل از وردپرس اجرا می‌شود. نسخه 2.0.1 هدف prepend را با stub بی‌ضرر خنثی می‌کند،
dropperهای بازتولیدکننده و cron مخرب را می‌یابد، و محافظ‌های موقت را تا ۴۸ ساعت نگه می‌دارد.

اگر پاک‌سازی داخل وردپرس کافی نبود:

1. `sources/mvn-emergency-clean.php` را باز کنید و `MVN_TOKEN` را به یک رمز بلند و تصادفی تغییر دهید.
2. فایل را کنار `wp-config.php` آپلود کنید و فقط با `POST` و هدر `Authorization: Bearer TOKEN` اجرا کنید؛ token در URL ممنوع است.
3. فایل اضطراری را بلافاصله حذف کنید.
4. از میزبان بخواهید PHP-FPM را ری‌استارت کند تا کش `.user.ini` پاک شود.
5. تمام رمزها، FTP، دیتابیس و saltهای وردپرس را تعویض کنید.

ابزار اضطراری با token پیش‌فرض اصلاً اجرا نمی‌شود.

## مدل امنیتی نسخه 2.0

- موتور اسکن و امضاهای همراه کاملاً آفلاین کار می‌کنند. checksum، دانلود تعمیر و reputation فقط با اقدام/تنظیم opt-in آنلاین می‌شوند.
- رفع خودکار فقط برای `confidence >= 95` و IoC قطعی/چند شاهد مستقل است؛ امتیاز 65–94 تأیید مدیر می‌خواهد و کمتر از 65 فقط گزارش یا ignore می‌شود.
- هر mutation با snapshot/قرنطینه، write اتمیک، verify و rollback انجام می‌شود. payload قرنطینه بیرون webroot نگهداری و در fallback با authenticated encryption محافظت می‌شود.
- بسته remote فقط با `MVN_SIGNATURE_PACK_PUBLIC_KEY`، detached Ed25519 و host ثابت `MVN_SIGNATURE_PACK_HOST` فعال است؛ redirect، IP خصوصی و rollback نسخه رد می‌شوند.

## زمان‌بندی و system cron

اسکن سریع افزایشی روزانه و اسکن کامل هفتگی با single-event و lock اجرا می‌شود. اگر `DISABLE_WP_CRON` فعال است:

```text
*/5 * * * * wp --path=/path/to/wordpress cron event run --due-now --quiet
```

## Nginx و data retention

برای جلوگیری از اجرای PHP در uploads:

```nginx
location ~* ^/wp-content/uploads/.*\.(php[0-9]?|phtml|pht|phar)$ { deny all; }
```

قرنطینه به‌طور پیش‌فرض 30 روز، حداکثر 500 entry و 512MB نگهداری می‌شود. audit JSONL پس از 10MB rotate و فایل‌های قدیمی‌تر از 180 روز حذف می‌شوند؛ همه سقف‌ها filterable هستند.

## بازیابی و WP-CLI

- `wp mvn scan [--full]`
- `wp mvn status`
- `wp mvn quarantine list`
- `wp mvn quarantine restore ID [--force]`
- `wp mvn repair verify`

بعد از رخداد: credentialها و saltها را rotate، PHP-FPM را restart، رخداد را دوباره scan و فقط در وضعیت `verified` بسته تلقی کنید.

## نکات

- قبل از هر حذف/پاکسازی، snapshot در data-dir اختصاصی ذخیره می‌شود.
- `wp-config.php` و پوشه `wp-content` هنگام تعمیر هسته دست‌نخورده می‌مانند.
- روی ویندوز/WAMP، `chmod` ممکن است اثر واقعی نداشته باشد؛ روی لینوکس هاست واقعی اثر دارد.

## نیازمندی‌ها

- PHP 7.4+
- افزونه PHP `ZipArchive`
- وردپرس 5.6+
