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
- **پاک‌سازی پایدار xdav-tracker** (حذف IoC + scrub option/active_plugins)
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

## نکات

- قبل از هر حذف/پاکسازی، فایل در `wp-content/mvn-data/quarantine` ذخیره می‌شود.
- `wp-config.php` و پوشه `wp-content` هنگام تعمیر هسته دست‌نخورده می‌مانند.
- روی ویندوز/WAMP، `chmod` ممکن است اثر واقعی نداشته باشد؛ روی لینوکس هاست واقعی اثر دارد.

## نیازمندی‌ها

- PHP 7.4+
- افزونه PHP `ZipArchive`
- وردپرس 5.6+
