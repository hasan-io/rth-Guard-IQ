<?php
// C:\xampp\htdocs\defsec\v2\api\collect.php
// Receives data from tracker snippet on client websites

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Allow all origins (cross-site requests)
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request (CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST only']);
    exit();
}

require_once __DIR__ . '/../includes/db.php';

// =============================================
// Read incoming JSON data
// =============================================
$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!$data) {
    echo json_encode(['success' => false, 'error' => 'Invalid JSON']);
    exit();
}

// =============================================
// Validate API Key
// =============================================
$apiKey = $data['api_key'] ?? '';

if (empty($apiKey)) {
    echo json_encode(['success' => false, 'error' => 'API key required']);
    exit();
}

try {
    // Find user + website by API key
    $stmt = $pdo->prepare("
        SELECT u.id as user_id, w.id as website_id, w.site_name, w.domain
        FROM users u
        JOIN websites w ON w.user_id = u.id
        WHERE u.api_key = ?
        AND u.status = 'active'
        LIMIT 1
    ");
    $stmt->execute([$apiKey]);
    $account = $stmt->fetch();

    if (!$account) {
        echo json_encode(['success' => false, 'error' => 'Invalid API key']);
        exit();
    }

    $websiteId = $account['website_id'];
    $userId    = $account['user_id'];

    // =============================================
    // Extract visitor data
    // =============================================
    $ip         = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ip         = explode(',', $ip)[0]; // First IP if multiple
    $ip         = trim($ip);

    $userAgent  = $data['user_agent']  ?? $_SERVER['HTTP_USER_AGENT'] ?? '';
    $pageUrl    = $data['page_url']    ?? '';
    $referrer   = $data['referrer']    ?? '';
    $screenRes  = $data['screen']      ?? '';
    $language   = $data['language']    ?? '';
    $timezone   = $data['timezone']    ?? '';
    $platform   = $data['platform']    ?? '';
    $fingerprint = $data['fingerprint'] ?? '';

    // =============================================
    // Basic Geo lookup (ip-api.com free)
    // =============================================
    $country   = 'Unknown';
    $city      = 'Unknown';
    $isp       = 'Unknown';
    $latitude  = 0;
    $longitude = 0;
    $isVpn     = 0;
    $isProxy   = 0;

    // Only do geo lookup for real IPs
    if ($ip !== '127.0.0.1' && $ip !== '::1' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
        $geoUrl  = "http://ip-api.com/json/{$ip}?fields=status,country,city,isp,lat,lon,proxy,hosting";
        $context = stream_context_create(['http' => ['timeout' => 3]]);
        $geoRaw  = @file_get_contents($geoUrl, false, $context);

        if ($geoRaw) {
            $geo = json_decode($geoRaw, true);
            if ($geo && $geo['status'] === 'success') {
                $country   = $geo['country']  ?? 'Unknown';
                $city      = $geo['city']     ?? 'Unknown';
                $isp       = $geo['isp']      ?? 'Unknown';
                $latitude  = $geo['lat']      ?? 0;
                $longitude = $geo['lon']      ?? 0;
                $isProxy   = ($geo['proxy']   ?? false) ? 1 : 0;
                $isVpn     = ($geo['hosting'] ?? false) ? 1 : 0;
            }
        }
    } else {
        // Localhost testing
        $country = 'Localhost';
        $city    = 'Local';
    }

    // =============================================
    // Save to logs table — exact column names
    // =============================================
    $stmt = $pdo->prepare("
        INSERT INTO logs (
            user_id, website_id,
            ip, real_ip,
            country, city, ISP,
            latitude, longitude,
            is_vpn, is_proxy,
            user_agent, screen_resolution,
            language, timezone,
            digital_dna, referrer,
            location_source,
            timestamp
        ) VALUES (
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            'ip',
            NOW()
        )
    ");
    $stmt->execute([
        $userId, $websiteId,
        $ip, $ip,
        $country, $city, $isp,
        $latitude, $longitude,
        $isVpn, $isProxy,
        $userAgent, $screenRes,
        $language, $timezone,
        $fingerprint, $referrer
    ]);
    $logId = $pdo->lastInsertId();

    // =============================================
    // Attack Detection
    // =============================================
    $attackDetected = false;
    $attackType     = '';
    $attackSeverity = 'low';
    $payload        = '';

    // Check URL params + form inputs for attacks
    $checkTargets = [
        'page_url' => $pageUrl,
        'referrer' => $referrer,
        'input'    => $data['form_input'] ?? '',
    ];

    foreach ($checkTargets as $source => $value) {
        if (empty($value)) continue;

        // XSS Detection
        if (preg_match('/<script[\s>]|javascript:|on\w+\s*=|<iframe|alert\s*\(|document\.cookie|eval\s*\(/i', $value)) {
            $attackDetected = true;
            $attackType     = 'XSS';
            $attackSeverity = 'high';
            $payload        = substr($value, 0, 500);
            break;
        }

        // SQL Injection Detection
        if (preg_match('/(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|\binsert\b.*\binto\b|\bdelete\b.*\bfrom\b|--|\/\*|\*\/|xp_|exec\s*\(|0x[0-9a-f]+)/i', $value)) {
            $attackDetected = true;
            $attackType     = 'SQL Injection';
            $attackSeverity = 'critical';
            $payload        = substr($value, 0, 500);
            break;
        }

        // Path Traversal
        if (preg_match('/\.\.[\/\\\\]|\/etc\/passwd|\/windows\/system32/i', $value)) {
            $attackDetected = true;
            $attackType     = 'Path Traversal';
            $attackSeverity = 'high';
            $payload        = substr($value, 0, 500);
            break;
        }

        // Command Injection
        if (preg_match('/;\s*(ls|cat|rm|wget|curl|bash|sh|cmd|powershell)\s|`[^`]+`|\$\([^)]+\)/i', $value)) {
            $attackDetected = true;
            $attackType     = 'Command Injection';
            $attackSeverity = 'critical';
            $payload        = substr($value, 0, 500);
            break;
        }
    }

    // =============================================
    // Save attack if detected
    // =============================================
    // Save attack if detected
    if ($attackDetected) {
    $stmt = $pdo->prepare("
        INSERT INTO attack_logs (
            user_id, website_id,
            attack_type, severity,
            ip_address, user_agent,
            attack_payload, request_url
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
        $userId, $websiteId,
        $attackType, $attackSeverity,
        $ip, $userAgent,
        $payload, $pageUrl
    ]);
    $attackId = (int)$pdo->lastInsertId();

    // Email alert
    require_once __DIR__ . '/send-alert.php';

    $attackDataForEmail = [
        'attack_type' => $attackType,
        'severity'    => $attackSeverity,
        'ip_address'  => $ip,
        'timestamp'   => date('Y-m-d H:i:s'),
    ];

    // User email fetch karo
    $emailStmt = $pdo->prepare("SELECT email, full_name FROM users WHERE id = ? LIMIT 1");
    $emailStmt->execute([$userId]);
    $userInfo = $emailStmt->fetch();

    if ($userInfo) {
        sendAttackAlert(
            $attackId,
            $userInfo['email'],
            $account['site_name'],
            $attackDataForEmail
        );
    }
}

    // =============================================
    // Response
    // =============================================
    echo json_encode([
        'success'         => true,
        'tracked'         => true,
        'attack_detected' => $attackDetected,
        'attack_type'     => $attackType ?: null,
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>