<?php
// ==========================
// DB CONNECTION
// ==========================
$db = new mysqli("localhost", "root", "", "mailfor");

if ($db->connect_error) {
    http_response_code(500);
    exit("Database connection failed");
}

// ==========================
// HARDCODED FOR NOW (replace with dynamic later)
// ==========================
$userId = 1;
$websiteId = 1;

// ==========================
// GET CLIENT IP
// ==========================
$clientIp = $_SERVER['HTTP_CF_CONNECTING_IP']
    ?? $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['REMOTE_ADDR'];

// Clean up forwarded IPs (comma separated)
if (str_contains($clientIp, ',')) {
    $clientIp = trim(explode(',', $clientIp)[0]);
}

// Local testing fallback - use a real IP for testing
if ($clientIp === '127.0.0.1' || $clientIp === '::1') {
    $clientIp = '8.8.8.8'; // Google DNS - US IP for testing
}

// ==========================
// CHECK BLOCKED IPS FIRST
// ==========================
$stmt = $db->prepare("
    SELECT id FROM blocked_ips 
    WHERE ip = ? 
    AND user_id = ? 
    AND website_id = ?
");
$stmt->bind_param("sii", $clientIp, $userId, $websiteId);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $stmt->close();
    $db->close();
    http_response_code(403);
    include __DIR__ . '/../err/403.php';
    exit;
}
$stmt->close();

// ==========================
// LOAD SETTINGS
// ==========================
$settings = [
    'block_vpn'    => '0',
    'strict_mode'  => '0',
    'geo_blocking' => '0'
];

$stmt = $db->prepare("
    SELECT setting_name, setting_value 
    FROM settings 
    WHERE user_id = ? AND website_id = ?
");
$stmt->bind_param("ii", $userId, $websiteId);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $settings[$row['setting_name']] = $row['setting_value'];
}
$stmt->close();

// ==========================
// GEO + VPN LOOKUP
// ip-api.com pro fields: proxy, hosting, vpn
// Free plan workaround: use multiple signals
// ==========================
$geoApiUrl = "http://ip-api.com/json/{$clientIp}?fields=status,message,country,countryCode,proxy,hosting,org,isp";
$response = @file_get_contents($geoApiUrl);
$geoData = json_decode($response, true);

if (!$geoData || $geoData['status'] !== 'success') {
    // If geo lookup fails, allow access but log it
    $geoData = [
        'country'     => 'Unknown',
        'countryCode' => 'XX',
        'proxy'       => false,
        'hosting'     => false,
        'org'         => '',
        'isp'         => ''
    ];
}

$countryCode = $geoData['countryCode'] ?? 'XX';
$country     = $geoData['country'] ?? 'Unknown';

// ==========================
// BETTER VPN/PROXY DETECTION
// Multiple signals se detect karo
// ==========================
$isVpnOrProxy = false;

// Signal 1: ip-api proxy field
if (!empty($geoData['proxy'])) {
    $isVpnOrProxy = true;
}

// Signal 2: Hosting/datacenter IP (VPNs often use these)
if (!empty($geoData['hosting'])) {
    $isVpnOrProxy = true;
}

// Signal 3: Known VPN/proxy keywords in ISP or Org name
$vpnKeywords = [
    'vpn', 'proxy', 'tor', 'mullvad', 'nordvpn', 'expressvpn',
    'surfshark', 'protonvpn', 'cyberghost', 'ipvanish', 'hidemyass',
    'tunnelbear', 'windscribe', 'privateinternetaccess', 'pia',
    'hosting', 'datacenter', 'data center', 'server', 'cloud',
    'digitalocean', 'linode', 'vultr', 'amazon', 'aws', 'azure',
    'google cloud', 'cloudflare', 'ovh', 'hetzner'
];

$orgLower = strtolower($geoData['org'] ?? '');
$ispLower = strtolower($geoData['isp'] ?? '');

foreach ($vpnKeywords as $keyword) {
    if (str_contains($orgLower, $keyword) || str_contains($ispLower, $keyword)) {
        $isVpnOrProxy = true;
        break;
    }
}

// ==========================
// VPN BLOCK CHECK
// ==========================
if ($settings['block_vpn'] === '1' && $isVpnOrProxy) {
    // Log the blocked attempt
    $stmt = $db->prepare("
        INSERT INTO attack_logs 
        (user_id, website_id, timestamp, attack_type, severity, ip_address, user_agent, attack_payload, request_url)
        VALUES (?, ?, NOW(), 'VPN_BLOCKED', 'Medium', ?, ?, 'VPN/Proxy detected and blocked', ?)
    ");
    $ua  = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $stmt->bind_param("iisss", $userId, $websiteId, $clientIp, $ua, $uri);
    $stmt->execute();
    $stmt->close();

    $db->close();
    http_response_code(403);
    include __DIR__ . '/../err/403.php';
    exit;
}

// ==========================
// GEO-BLOCKING + STRICT MODE CHECK
// ==========================
if ($settings['geo_blocking'] === '1') {
    $stmt = $db->prepare("
        SELECT is_allowed 
        FROM allowed_countries 
        WHERE country_code = ? AND user_id = ? AND website_id = ?
    ");
    $stmt->bind_param("sii", $countryCode, $userId, $websiteId);
    $stmt->execute();
    $result = $stmt->get_result();

    $shouldBlock = false;

    if ($result->num_rows > 0) {
        // Country is in list - check if allowed or blocked
        $row = $result->fetch_assoc();
        if (!$row['is_allowed']) {
            $shouldBlock = true; // Explicitly blocked
        }
    } else {
        // Country not in list
        if ($settings['strict_mode'] === '1') {
            $shouldBlock = true; // Strict mode: block if not in whitelist
        }
    }
    $stmt->close();

    if ($shouldBlock) {
        // Log blocked country attempt
        $stmt = $db->prepare("
            INSERT INTO attack_logs 
            (user_id, website_id, timestamp, attack_type, severity, ip_address, user_agent, attack_payload, request_url)
            VALUES (?, ?, NOW(), 'GEO_BLOCKED', 'Low', ?, ?, ?, ?)
        ");
        $ua      = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $uri     = $_SERVER['REQUEST_URI'] ?? '/';
        $payload = "Country blocked: {$country} ({$countryCode})";
        $stmt->bind_param("iissss", $userId, $websiteId, $clientIp, $ua, $payload, $uri);
        $stmt->execute();
        $stmt->close();

        $db->close();
        http_response_code(403);
        include __DIR__ . '/../err/403.php';
        exit;
    }
}

// ==========================
// LOG SUCCESSFUL ACCESS
// ==========================
$stmt = $db->prepare("
    INSERT INTO access_logs 
    (user_id, website_id, ip_address, user_agent, referrer, request_uri, http_method, query_string) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
");
$ua          = $_SERVER['HTTP_USER_AGENT'] ?? '';
$referrer    = $_SERVER['HTTP_REFERER'] ?? '';
$requestUri  = $_SERVER['REQUEST_URI'] ?? '';
$httpMethod  = $_SERVER['REQUEST_METHOD'] ?? '';
$queryString = $_SERVER['QUERY_STRING'] ?? '';

$stmt->bind_param("iissssss", $userId, $websiteId, $clientIp, $ua, $referrer, $requestUri, $httpMethod, $queryString);
$stmt->execute();
$stmt->close();

$db->close();