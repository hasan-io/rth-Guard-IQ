<?php
require_once __DIR__ . '/PHPMailer/src/Exception.php';
require_once __DIR__ . '/PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/PHPMailer/src/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = 'apexdevhub@gmail.com';
    $mail->Password   = 'emnntwffotqhhwok';
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;
    $mail->SMTPDebug  = 2; // Full debug output

    $mail->setFrom('apexdevhub@gmail.com', 'Guard IQ');
    $mail->addAddress('hasansayyad912@gmail.com');
    $mail->Subject = 'Guard IQ Test Email';
    $mail->Body    = 'Agar ye aaya toh PHPMailer kaam kar raha hai!';

    $mail->send();
    echo "EMAIL SENT SUCCESSFULLY!";

} catch (Exception $e) {
    echo "ERROR: " . $mail->ErrorInfo;
}
?>