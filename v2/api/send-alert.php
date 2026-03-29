<?php
/**
 * Guard IQ — send-alert.php
 * Attack detect hone pe Gmail SMTP se email alert bhejta hai
 * Directly call mat karo — collect.php internally call karta hai
 */
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'C:/xampp/htdocs/defsec/v2/mail_error.log');

require_once __DIR__ . '/../PHPMailer/src/Exception.php';
require_once __DIR__ . '/../PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/../PHPMailer/src/SMTP.php';
date_default_timezone_set('Asia/Kolkata');

global $pdo;
if (!isset($pdo)) {
    require_once __DIR__ . '/../includes/db.php';
}

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// ============================================================
// GMAIL CONFIG
// ============================================================
define('MAIL_USERNAME', 'apexdevhub@gmail.com');
define('MAIL_PASSWORD', 'emnntwffotqhhwok');
define('MAIL_FROM_NAME', 'Guard IQ Security');
define('GUARD_IQ_BASE_URL', 'http://localhost/defsec/v2');
// ============================================================

/**
 * Attack alert email bhejo
 *
 * @param int    $attack_id   attack_logs table ka ID
 * @param string $to_email    User ka registered email
 * @param string $site_name   Website ka naam (e.g., "apexx")
 * @param array  $attack_data Attack ki details
 * @return bool  Success ya failure
 */
function sendAttackAlert(int $attack_id, string $to_email, string $site_name, array $attack_data): bool {
    // Unique report token generate karo
    $token = bin2hex(random_bytes(32)); // 64 char hex token

    // Token DB me save karo
    try {
        global $pdo;
$stmt = $pdo->prepare(
            "UPDATE attack_logs SET report_token = ?, token_created_at = NOW() WHERE id = ?"
        );
        $stmt->execute([$token, $attack_id]);
    } catch (Exception $e) {
        error_log("Guard IQ: Token save failed — " . $e->getMessage());
        return false;
    }

    // Report URL
    $report_url = GUARD_IQ_BASE_URL . "/report.php?token=" . $token;

    // Severity color mapping
    $severity = strtoupper($attack_data['severity'] ?? 'HIGH');
    $severity_colors = [
        'CRITICAL' => '#ff2d2d',
        'HIGH'     => '#ff6b35',
        'MEDIUM'   => '#ffa500',
        'LOW'      => '#ffd700',
    ];
    $severity_color = $severity_colors[$severity] ?? '#ff6b35';

    // Attack type clean naam
    $attack_type = htmlspecialchars($attack_data['attack_type'] ?? 'Unknown Attack');
    $attacker_ip = htmlspecialchars($attack_data['ip_address'] ?? 'Unknown');
    $timestamp   = date('d M Y, h:i A', strtotime($attack_data['timestamp'] ?? 'now'));
    $site_clean  = htmlspecialchars($site_name);

    // Email HTML body
    $html_body = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Guard IQ — Security Alert</title>
</head>
<body style="margin:0;padding:0;background-color:#0a0a0f;font-family:'Courier New',Courier,monospace;">

<!-- Outer wrapper -->
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0a0f;padding:40px 20px;">
  <tr>
    <td align="center">

      <!-- Card -->
      <table width="600" cellpadding="0" cellspacing="0"
             style="max-width:600px;background:#0f0f1a;border:1px solid #1e1e3a;border-radius:12px;overflow:hidden;">

        <!-- Top alert bar -->
        <tr>
          <td style="background:{$severity_color};padding:6px 24px;text-align:center;">
            <span style="color:#000;font-size:12px;font-weight:bold;letter-spacing:3px;text-transform:uppercase;">
              ⚠ SECURITY ALERT — {$severity} SEVERITY
            </span>
          </td>
        </tr>

        <!-- Logo + Header -->
        <tr>
          <td style="padding:32px 32px 16px;border-bottom:1px solid #1e1e3a;">
            <table width="100%">
              <tr>
                <td>
                  <div style="font-size:11px;color:#4a9eff;letter-spacing:4px;text-transform:uppercase;margin-bottom:6px;">
                    GUARD IQ SECURITY
                  </div>
                  <div style="font-size:22px;font-weight:bold;color:#ffffff;line-height:1.3;">
                    🔴 Unauthorized Attack<br>Detected on <span style="color:{$severity_color};">{$site_clean}</span>
                  </div>
                </td>
                <td width="60" valign="top" align="right">
                  <div style="width:48px;height:48px;background:{$severity_color};border-radius:50%;
                              display:inline-flex;align-items:center;justify-content:center;
                              font-size:22px;line-height:48px;text-align:center;">🛡</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Body text -->
        <tr>
          <td style="padding:24px 32px;color:#a0a0b8;font-size:14px;line-height:1.7;">
            Guard IQ Security has detected a <strong style="color:#ffffff;">{$severity} Security Threat</strong>
            targeting your website <strong style="color:{$severity_color};">{$site_clean}</strong>.
            An unauthorized attack attempt has been identified and logged.
            We have captured the attacker's details and generated a full report for your review.
          </td>
        </tr>

        <!-- Attack details box -->
        <tr>
          <td style="padding:0 32px 24px;">
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="background:#0a0a14;border:1px solid #1e1e3a;border-radius:8px;overflow:hidden;">
              <tr>
                <td style="padding:12px 20px;border-bottom:1px solid #1e1e3a;background:#12122a;">
                  <span style="color:#4a9eff;font-size:11px;letter-spacing:3px;text-transform:uppercase;">
                    ATTACK DETAILS
                  </span>
                </td>
              </tr>
              <tr>
                <td style="padding:16px 20px;">
                  <table width="100%" cellpadding="6" cellspacing="0">
                    <tr>
                      <td style="color:#606080;font-size:12px;width:140px;">Attack Type</td>
                      <td style="color:{$severity_color};font-size:13px;font-weight:bold;">{$attack_type}</td>
                    </tr>
                    <tr>
                      <td style="color:#606080;font-size:12px;">Severity</td>
                      <td style="color:{$severity_color};font-size:13px;font-weight:bold;">{$severity}</td>
                    </tr>
                    <tr>
                      <td style="color:#606080;font-size:12px;">Attacker IP</td>
                      <td style="color:#ffffff;font-size:13px;">{$attacker_ip}</td>
                    </tr>
                    <tr>
                      <td style="color:#606080;font-size:12px;">Detected At</td>
                      <td style="color:#ffffff;font-size:13px;">{$timestamp}</td>
                    </tr>
                    <tr>
                      <td style="color:#606080;font-size:12px;">Target Site</td>
                      <td style="color:#ffffff;font-size:13px;">{$site_clean}</td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- CTA Button -->
        <tr>
          <td style="padding:8px 32px 32px;text-align:center;">
            <a href="{$report_url}"
               style="display:inline-block;background:{$severity_color};color:#000000;
                      text-decoration:none;font-weight:bold;font-size:14px;letter-spacing:1px;
                      padding:14px 36px;border-radius:6px;text-transform:uppercase;">
              📋 VIEW FULL ATTACK REPORT
            </a>
            <div style="margin-top:12px;color:#404060;font-size:11px;">
              This link does not require login. Shareable with your security team.
            </div>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 32px;border-top:1px solid #1e1e3a;text-align:center;">
            <div style="color:#404060;font-size:11px;letter-spacing:1px;">
              — Team Guard IQ &nbsp;|&nbsp; Automated Security Alert &nbsp;|&nbsp;
              <a href="{GUARD_IQ_BASE_URL}" style="color:#4a9eff;text-decoration:none;">Dashboard</a>
            </div>
            <div style="color:#2a2a4a;font-size:10px;margin-top:8px;">
              You received this because you registered this website with Guard IQ.
            </div>
          </td>
        </tr>

      </table>
      <!-- /Card -->

    </td>
  </tr>
</table>

</body>
</html>
HTML;

    // Plain text fallback
    $plain_body = "GUARD IQ SECURITY ALERT\n\n"
        . "Attack detected on: {$site_clean}\n"
        . "Attack Type: {$attack_type}\n"
        . "Severity: {$severity}\n"
        . "Attacker IP: {$attacker_ip}\n"
        . "Detected At: {$timestamp}\n\n"
        . "View Full Report: {$report_url}\n\n"
        . "— Team Guard IQ";

    // PHPMailer send
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = MAIL_USERNAME;
        $mail->Password   = str_replace(' ', '', MAIL_PASSWORD); // spaces hata do App Password se
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;
        $mail->SMTPOptions = [
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
            ],
        ];

        // Recipients
        $mail->setFrom(MAIL_USERNAME, MAIL_FROM_NAME);
        $mail->addAddress($to_email);
        $mail->addReplyTo(MAIL_USERNAME, MAIL_FROM_NAME);

        // Content
        $mail->isHTML(true);
        $mail->CharSet = 'UTF-8';
        $mail->Encoding = 'base64';
        $mail->Subject = "=?UTF-8?B?" . base64_encode("🔴 {$severity} THREAT: Unauthorized attack detected on {$site_clean}") . "?=";
        $mail->Body    = $html_body;
        $mail->AltBody = $plain_body;

        $mail->send();
        error_log("Guard IQ: Alert email sent to {$to_email} for attack ID {$attack_id}");
        return true;

    } catch (\PHPMailer\PHPMailer\Exception $e) {
        error_log("Guard IQ: Email failed — " . $mail->ErrorInfo);
        return false;
    }
}