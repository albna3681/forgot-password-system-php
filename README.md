# صفحة نسيان كلمة السر مع ربطها بقاعدة البيانات وإرسال رمز التحقق مع تحديد عدد المحاولات 🔐

## نظام متكامل لإعادة تعيين كلمة المرور بأمان عالي، مع حماية من الهجمات وتحديد عدد محاولات إرسال رمز التحقق للبريد الإلكتروني ، يعني باختصار هي صفحة بيدخل المشتخدم الايميل بتاعه بعدين يتم فحص هل الايميل موجود ولا لا لو موجود يبدا انه يحوله ل جزء تغيير كلمة السر ويبعت كود التحقق على الايميل بعدين يبدا انه يفتح جزء تغيير كلمة السر وادخال كود التحقق والباسورد الجديد وتاكيده ولو الكود صح هيتم تغيير الباسورد وكمان موجود انه يتم ظبط انه المستخدم اخره 3 محاولات في عشر دقائق

## معاينة الصفحات 

##  اولا صفحة ادخال الايميل والتاكد انه موجود في قاعدة البيانات 
![](https://github.com/albna3681/forgot-password-system-php/blob/main/FireShot%20Capture%20045%20-%20%D8%A7%D8%B3%D8%AA%D8%B9%D8%A7%D8%AF%D8%A9%20%D9%83%D9%84%D9%85%D8%A9%20%D8%A7%D9%84%D9%85%D8%B1%D9%88%D8%B1%20-%20%5Baldhihaexams.com%5D.png)

##  ثانيا لو موجود يرسل الكود ويفتح جزء تغيير كلمة السر وكتابة كود التحقق
![](https://github.com/albna3681/forgot-password-system-php/blob/main/FireShot%20Capture%20046%20-%20%D8%A7%D8%B3%D8%AA%D8%B9%D8%A7%D8%AF%D8%A9%20%D9%83%D9%84%D9%85%D8%A9%20%D8%A7%D9%84%D9%85%D8%B1%D9%88%D8%B1%20-%20%5Baldhihaexams.com%5D.png)


##  ده كود التحقق وهو تم ارساله لايميل المستخدم اللي دخله
![](https://github.com/albna3681/forgot-password-system-php/blob/main/FireShot%20Capture%20048%20-%20%D8%B1%D9%85%D8%B2%20%D8%A7%D9%84%D8%AA%D8%AD%D9%82%D9%82%20%D9%84%D8%A7%D8%B3%D8%AA%D8%B9%D8%A7%D8%AF%D8%A9%20%D9%83%D9%84%D9%85%D8%A9%20%D8%A7%D9%84%D9%85%D8%B1%D9%88%D8%B1%20-%20almligy20118%40gmail.com%20-%20Gmail_%20-%20%5Bmail.google.com%5D.png)


##  ده بعد ما تم تغيير كلمة السر
![](https://github.com/albna3681/forgot-password-system-php/blob/main/FireShot%20Capture%20049%20-%20%D8%A7%D8%B3%D8%AA%D8%B9%D8%A7%D8%AF%D8%A9%20%D9%83%D9%84%D9%85%D8%A9%20%D8%A7%D9%84%D9%85%D8%B1%D9%88%D8%B1%20-%20%5Baldhihaexams.com%5D.png)



## ✨ المميزات الرئيسية

- 🔒 **تشفير آمن** لكلمات المرور باستخدام PHP password_hash
- 📧 **إرسال رمز التحقق** للبريد الإلكتروني بتصميم HTML احترافي
- 🛡️ **حماية من الهجمات** - تحديد عدد المحاولات (3 محاولات كل 10 دقائق)
- ⏱️ منع إرسال رموز متكررة
- 🎨 **واجهة عربية متجاوبة** تعمل على جميع الأجهزة

## 📋 متطلبات التشغيل

- PHP 7.4 أو أحدث
- MySQL/MariaDB
- Composer
- خدمة إرسال إيميل (SMTP)
- مساحة تخزين للـ Sessions

## 🛠️ التثبيت والإعداد

⚙️ ملف الإعداد (db_config.php)


<?php
$servername = "localhost";
$username = "your_username";
$password = "your_password";
$dbname = "your_database";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("فشل الاتصال: " . $conn->connect_error);
}

$conn->set_charset("utf8");
?>

### : تثبيت المكتبات المطلوبة
تثبيت Composer إذا لم يكن مثبت
curl -sS https://getcomposer.org/installer | php

تثبيت PHPMailer
composer require phpmailer/phpmailer

لف composer.json

json
{
    "require": {
        "phpmailer/phpmailer": "^6.8"
    }
}
 

###  إعداد قاعدة البيانات

**استخدم جدول المستخدمين الموجود** (تأكد من وجود الأعمدة المطلوبة):
-- تحقق من جدول users الموجود
SELECT * FROM users LIMIT 1;

-- إضافة الأعمدة إذا لم تكن موجودة
ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password VARCHAR(255);


احنا هنستخدم في الجدول عمود بتاع كلمة السر انه هنغيرها بعد ما نتاكد انه الكود اللي وصل للايميل دخله صح وبالتالي بعد التاكيد و صح وغير كلمة السر بنغيرها في جدول بتاع كلمة السر وبنشفرها وبنحفظها متشفرة في قاعدة البيانات في الجدول لو انت مش عايز تشفرها شيل التشفير بتاعها

**إنشاء جدول تتبع المحاولات** (جدول جديد):
CREATE TABLE password_reset_attempts (
id INT PRIMARY KEY AUTO_INCREMENT,
email VARCHAR(255) NOT NULL,
attempts INT DEFAULT 1,
first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
INDEX idx_email (email),
INDEX idx_first_attempt (first_attempt)
);



## 📧 إعداد خدمة الإيميل على حسب مانت عايز تستخدم 

### الخيار الأول: Gmail SMTP (مُوصى به)
// في الملف بتاع الكود بتاعنا
$mail->Host = 'smtp.gmail.com';
$mail->Username = 'your-email@gmail.com';
$mail->Password = 'your-app-password'; // App Password من Google
$mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
$mail->Port = 465;


 

**إعداد Gmail:**
1. فعل التحقق بخطوتين في حساب Google
2. اذهب لـ [App Passwords](https://myaccount.google.com/apppasswords)
3. أنشئ App Password جديد للتطبيق
4. استخدم الباسورد المُولد في الكود

### الخيار الثاني: SMTP الاستضافة 
$mail->Host = 'mail.yourdomain.com'; // أو localhost
$mail->Username = 'noreply@yourdomain.com';
$mail->Password = 'your-email-password';
$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;



### الخيار الثالث: Outlook/Hotmail
$mail->Host = 'smtp-mail.outlook.com';
$mail->Username = 'your-email@outlook.com';
$mail->Password = 'your-password';
$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;



## ⚙️ ملفات الإعداد

### ملف db_config.php
<?php $servername = "localhost"; // عنوان سيرفر قاعدة البيانات $username = "your_db_username"; // اسم مستخدم قاعدة البيانات $password = "your_db_password"; // كلمة مرور قاعدة البيانات $dbname = "your_database_name"; // اسم قاعدة البيانات $conn = new mysqli($servername, $username, $password, $dbname); if ($conn->connect_error) { die("فشل الاتصال: " . $conn->connect_error); } $conn->set_charset("utf8"); ?>



## 🔍 شرح الكود 

### 1. دالة إرسال الإيميل
function sendEmail($to, $subject, $message) {
// إعداد PHPMailer مع SMTP
// إرسال إيميل HTML منسق
// معالجة الأخطاء وتسجيلها
}



### 2. دالة توليد رمز التحقق
function generateVerificationCode() {
// توليد رمز عشوائي من 5 أرقام
return str_pad(rand(0, 99999), 5, '0', STR_PAD_LEFT);
}


 

### 3. دالة فحص المحاولات
function checkResetAttempts($email) {
// فحص عدد المحاولات للإيميل
// تطبيق قاعدة 3 محاولات كل 10 دقائق
// إعادة تعيين العداد بعد انتهاء المدة
}


 

### 4. نظام الحماية من التكرار
- **3 محاولات كحد أقصى** في فترة 10 دقائق
- **منع الإرسال** عند تجاوز الحد
- **إعادة تعيين تلقائية** للعداد بعد 10 دقائق
- **تسجيل جميع المحاولات** في قاعدة البيانات

### 5. تشفير كلمات المرور
// تشفير كلمة المرور الجديدة
$hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

// تحديث كلمة المرور في قاعدة البيانات في جدول مسمينه users  والعمود اسمه  password
$stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");


 

## 🚀 طريقة الاستخدام

### للمستخدم النهائي:
1. **دخول الإيميل** في الصفحة الأولى
2. **استلام رمز التحقق** على البريد الإلكتروني
3. **إدخال الرمز** مع كلمة المرور الجديدة
4. **تأكيد التغيير** والعودة لتسجيل الدخول

### للمطور:
1. ارفع الملفات على السيرفر
2. أنشئ جدول `password_reset_attempts`
3. عدل بيانات قاعدة البيانات في `db_config.php`
4. عدل بيانات SMTP في `forgotpass.php`
5. اختبر النظام

## 🔧 البيانات القابلة للتعديل

| البيان | الوصف | مثال |
|--------|--------|-------|
| `SMTP Host` | سيرفر الإيميل | `smtp.gmail.com` |
| `SMTP Username` | إيميل المرسل | `noreply@yoursite.com` |
| `SMTP Password` | كلمة مرور الإيميل | `your-app-password` |
| `SMTP Port` | منفذ الإرسال | `465` (SSL) أو `587` (TLS) |
| `Database Host` | سيرفر قاعدة البيانات | `localhost` |
| `Database Name` | اسم قاعدة البيانات | `your_database` |
| `Max Attempts` | عدد المحاولات المسموحة | `3` (قابل للتعديل في الكود) |
| `Timeout Period` | مدة الانتظار بالثواني | `600` (10 دقائق) |


## 📁 هيكل المشروع النهائي

forgot-password-system/
├── forgotpass.php # الملف الرئيسي للنظام
├── db_config.php # إعدادات الاتصال بقاعدة البيانات
├── database.sql # ملف إنشاء جدول password_reset_attempts
├── composer.json # ملف إعدادات Composer
├── composer.lock # قفل إصدارات المكتبات
├── vendor/ # مجلد المكتبات المثبتة
│ ├── phpmailer/ # مكتبة PHPMailer
│ └── autoload.php # ملف التحميل التلقائي
├── screenshots/ # صور المعاينة
│ ├── step1-email.png # صفحة إدخال الإيميل
│ ├── step2-code.png # صفحة إدخال الرمز
│ └── step3-success.png # صفحة النجاح
├── README.md # ملف التوثيق (هذا الملف)
├── LICENSE # ملف الترخيص
└── .gitignore # ملف استبعاد Git


 

## 📊 تفاصيل قاعدة البيانات

### جدول المستخدمين (موجود مسبقاً):
-- لا تنشئ هذا الجدول - استخدم الموجود
users (
id INT PRIMARY KEY, -- معرف المستخدم
email VARCHAR(255) UNIQUE, -- البريد الإلكتروني (مطلوب)
password VARCHAR(255), -- كلمة المرور المشفرة (مطلوب)
username VARCHAR(100), -- اسم المستخدم (اختياري)
created_at TIMESTAMP, -- تاريخ الإنشاء (اختياري)
-- ... باقي الأعمدة الموجودة
)


 

### جدول تتبع المحاولات (جديد):
CREATE TABLE password_reset_attempts (
id INT PRIMARY KEY AUTO_INCREMENT, -- معرف فريد
email VARCHAR(255) NOT NULL, -- الإيميل المحاول
attempts INT DEFAULT 1, -- عدد المحاولات
first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- أول محاولة
last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- آخر محاولة
INDEX idx_email (email), -- فهرس للبحث السريع
INDEX idx_first_attempt (first_attempt) -- فهرس للتنظيف التلقائي
);


 

## 🔄 سير العمل 

### المرحلة الأولى: طلب إعادة التعيين
1. المستخدم يدخل الإيميل
2. النظام يتحقق من وجود الإيميل في قاعدة البيانات
3. فحص عدد المحاولات السابقة
4. إرسال رمز التحقق إذا كان مسموحاً

### المرحلة الثانية: التحقق وإعادة التعيين
1. المستخدم يدخل الرمز وكلمة المرور الجديدة
2. التحقق من صحة الرمز
3. التحقق من قوة كلمة المرور
4. تشفير وحفظ كلمة المرور الجديدة

### المرحلة الثالثة: التنظيف
1. مسح بيانات الجلسة
2. إعادة توجيه لصفحة تسجيل الدخول
3. تسجيل العملية في اللوجز

