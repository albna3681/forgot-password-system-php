<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
require_once 'db_config.php';
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function sendEmail($to, $subject, $message) {
    try {
        $mail = new PHPMailer(true);
        
        
        $mail->isSMTP();
        $mail->Host       = '';
        $mail->SMTPAuth   = true;
        $mail->Username   = '';
        $mail->Password   = ''; 
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port       = 465;
        
        
        $mail->setFrom('', '');
        $mail->addAddress($to);
        
        
        $mail->CharSet = 'UTF-8';
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $message;
        
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Mail Error: {$mail->ErrorInfo}");
        return false;
    }
}


function generateVerificationCode() {
    return str_pad(rand(0, 99999), 5, '0', STR_PAD_LEFT);
}

function checkResetAttempts($email) {
    global $conn;
    $stmt = $conn->prepare("SELECT attempts, first_attempt, last_attempt FROM password_reset_attempts WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $currentTime = time();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $attempts = $row['attempts'];
        $firstAttempt = strtotime($row['first_attempt']);
        $lastAttempt = strtotime($row['last_attempt']);
        
        
        if ($currentTime - $firstAttempt >= 600) {
            
            $stmt = $conn->prepare("UPDATE password_reset_attempts SET attempts = 1, first_attempt = NOW(), last_attempt = NOW() WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            return true;
        }
        
        
        if ($attempts >= 3 && ($currentTime - $firstAttempt) < 600) {
            return false;
        }
        
        
        $stmt = $conn->prepare("UPDATE password_reset_attempts SET attempts = attempts + 1, last_attempt = NOW() WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
    } else {
        
        $stmt = $conn->prepare("INSERT INTO password_reset_attempts (email, attempts, first_attempt, last_attempt) VALUES (?, 1, NOW(), NOW())");
        $stmt->bind_param("s", $email);
        $stmt->execute();
    }
    
    return true;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['email'])) {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);

        if (!checkResetAttempts($email)) {
            echo json_encode(['success' => false, 'message' => 'لقد حاولت كثيراً. يرجى الانتظار عشر دقائق ثم المحاولة مرة أخرى.']);
            exit;
        }

        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $verificationCode = generateVerificationCode();
            $_SESSION['reset_email'] = $email;
            $_SESSION['verification_code'] = $verificationCode;

            $subject = "رمز التحقق لاستعادة كلمة المرور";
            $content = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; direction: rtl; }
                    .container { background-color: #f4f4f4; padding: 20px; }
                    .content { background-color: white; padding: 20px; border-radius: 5px; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='content'>
                        <h2>مرحباً،</h2>
                        <p>لقد تلقينا طلباً لاستعادة كلمة المرور الخاصة بحسابك.</p>
                        <p>رمز التحقق الخاص بك هو: <strong>$verificationCode</strong></p>
                        <p>يرجى استخدام هذا الرمز لإعادة تعيين كلمة المرور الخاصة بك.</p>
                        <p>إذا لم تقم بطلب استعادة كلمة المرور، يرجى تجاهل هذا البريد الإلكتروني.</p>
                    </div>
                </div>
            </body>
            </html>
            ";

            if (sendEmail($email, $subject, $content)) {
                echo json_encode(['success' => true, 'message' => 'تم إرسال رمز التحقق إلى بريدك الإلكتروني.']);
            } else {
                $error = error_get_last();
                error_log("Email sending failed. Error: " . print_r($error, true));
                echo json_encode(['success' => false, 'message' => 'حدث خطأ أثناء إرسال البريد الإلكتروني. يرجى المحاولة مرة أخرى لاحقاً.']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'البريد الإلكتروني غير موجود.']);
        }

        $stmt->close();
    } elseif (isset($_POST['verification_code']) && isset($_POST['new_password'])) {
        $verificationCode = $_POST['verification_code'];
        $newPassword = $_POST['new_password'];

        if (strlen($newPassword) < 8) {
            echo json_encode(['success' => false, 'message' => 'يجب أن تكون كلمة المرور 8 أحرف على الأقل.']);
            exit;
        }

        if ($verificationCode == $_SESSION['verification_code']) {
            $email = $_SESSION['reset_email'];
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
            $stmt->bind_param("ss", $hashedPassword, $email);
            
            if ($stmt->execute()) {
                echo json_encode(['success' => true, 'message' => 'تم تحديث كلمة المرور بنجاح.']);
                unset($_SESSION['reset_email']);
                unset($_SESSION['verification_code']);
            } else {
                echo json_encode(['success' => false, 'message' => 'حدث خطأ أثناء تحديث كلمة المرور.']);
            }

            $stmt->close();
        } else {
            echo json_encode(['success' => false, 'message' => 'رمز التحقق غير صحيح.']);
        }
    }

    $conn->close();
    exit;
}
?>


<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>استعادة كلمة المرور</title>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600&display=swap" rel="stylesheet">


    <style>
        body {
            font-family: 'Cairo', sans-serif;
            background-color: #f0f0f0;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: #333;
        }

        .container {
            background-color: rgba(255, 255, 255, 0.9);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            width: 90%;
            max-width: 400px; 
            display: flex;
            flex-direction: column;
            justify-content: center;
            transition: all 0.3s ease;
        }

        @media (min-width: 768px) {
            .container {
                max-width: 450px; 
                padding: 40px;
            }
        }

        @media (min-width: 1024px) {
            .container {
                max-width: 500px; 
            }
        }


        h1 {
            text-align: center;
            color: #4a4a4a;
            margin-bottom: 30px;
            font-weight: 600;
        }

        form {
            display: flex;
            flex-direction: column;
        }

        input, button {
            margin-bottom: 20px;
            padding: 15px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            transition: all 0.3s ease;
            width: 100%;
            box-sizing: border-box;
        }

        input {
            background-color: #f0f0f0;
            border: 2px solid transparent;
        }

        input:focus {
            border-color: #667eea;
            outline: none;
            box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
        }

        button {
            background-color: #667eea;
            color: white;
            cursor: pointer;
            font-weight: 600;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #5a6fd6;
        }

        .message {
            text-align: center;
            margin-bottom: 20px;
            padding: 10px;
            border-radius: 5px;
            font-weight: 500;
        }

        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .link {
            text-align: center;
            margin-top: 20px;
        }

        .link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .link a:hover {
            color: #5a6fd6;
        }

        .password-container {
            position: relative;
        }

        .toggle-password {
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #666;
        }
        
    </style>
</head>
<body>
    <div class="container">
        <h1>استعادة كلمة المرور</h1>
        <div id="message" class="message" style="display: none;"></div>
        <form id="forgotPasswordForm">
            <input type="email" name="email" placeholder="البريد الإلكتروني" required>
            <button type="submit">إرسال رمز التحقق</button>
        </form>
        <form id="resetPasswordForm" style="display: none;">
            <input type="text" name="verification_code" placeholder="رمز التحقق" required>
            <div class="password-container">
                <input type="password" name="new_password" placeholder="كلمة المرور الجديدة (8 أحرف على الأقل)" required minlength="8">
                <span class="toggle-password" onclick="togglePasswordVisibility('new_password')">👁️</span>
            </div>
            <div class="password-container">
                <input type="password" name="confirm_password" placeholder="تأكيد كلمة المرور الجديدة" required minlength="8">
                <span class="toggle-password" onclick="togglePasswordVisibility('confirm_password')">👁️</span>
            </div>
            <button type="submit">تحديث كلمة المرور</button>
        </form>
        <div class="link" id="backLink">
            <a href="login.php" id="backButton">العودة لتسجيل الدخول</a>
        </div>
    </div>

    <script>
        const forgotPasswordForm = document.getElementById('forgotPasswordForm');
        const resetPasswordForm = document.getElementById('resetPasswordForm');
        const backLink = document.getElementById('backLink');
        const backButton = document.getElementById('backButton');
        const messageDiv = document.getElementById('message');

        function showMessage(message, isSuccess) {
            messageDiv.textContent = message;
            messageDiv.className = 'message ' + (isSuccess ? 'success' : 'error');
            messageDiv.style.display = 'block';
        }

        function goToEmailForm() {
            resetPasswordForm.style.display = 'none';
            forgotPasswordForm.style.display = 'block';
            backButton.textContent = 'العودة لتسجيل الدخول';
            backButton.href = 'login.php';
        }

        backButton.addEventListener('click', function(e) {
            if (resetPasswordForm.style.display === 'block') {
                e.preventDefault();
                goToEmailForm();
            }
        });

        forgotPasswordForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var email = this.email.value;

            fetch('forgotpass.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'email=' + encodeURIComponent(email)
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message, data.success);
                if (data.success) {
                    this.style.display = 'none';
                    resetPasswordForm.style.display = 'block';
                    backButton.textContent = 'العودة';
                    backButton.href = '#';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showMessage('حدث خطأ. يرجى المحاولة مرة أخرى.', false);
            });
        });

        resetPasswordForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var verificationCode = this.verification_code.value;
            var newPassword = this.new_password.value;
            var confirmPassword = this.confirm_password.value;

            if (newPassword.length < 8) {
                showMessage('يجب أن تكون كلمة المرور 8 أحرف على الأقل.', false);
                return;
            }

            if (newPassword !== confirmPassword) {
                showMessage('كلمات المرور غير متطابقة.', false);
                return;
            }

            fetch('forgotpass.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'verification_code=' + encodeURIComponent(verificationCode) + '&new_password=' + encodeURIComponent(newPassword)
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message, data.success);
                if (data.success) {
                    this.style.display = 'none';
                    backButton.textContent = 'العودة إلى تسجيل الدخول';
                    backButton.href = 'login.php';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showMessage('حدث خطأ. يرجى المحاولة مرة أخرى.', false);
            });
        });

        function togglePasswordVisibility(fieldName) {
            var field = document.querySelector(`input[name="${fieldName}"]`);
            var type = field.getAttribute('type') === 'password' ? 'text' : 'password';
            field.setAttribute('type', type);
        }
    

document.addEventListener('keydown', function(e) {
    
    if (e.ctrlKey && e.shiftKey && e.keyCode === 73) {
        e.preventDefault();
    }
    
    if (e.ctrlKey && e.keyCode === 85) {
        e.preventDefault();
    }
});
document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
});

    </script>
</body>
</html>
