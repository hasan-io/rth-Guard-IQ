<?php
session_start();
require_once '../includes/db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

$ip = $_POST['ip'] ?? '';
$websiteId = $_POST['website_id'] ?? 1;
$userId = $_SESSION['user_id'];
$reason = $_POST['reason'] ?? 'Manually blocked from dashboard';

if (empty($ip)) {
    echo json_encode(['success' => false, 'message' => 'IP address required']);
    exit;
}

try {
    // Check if already blocked
    $check = $pdo->prepare("SELECT id FROM blocked_ips WHERE ip = ? AND user_id = ? AND website_id = ?");
    $check->execute([$ip, $userId, $websiteId]);
    
    if ($check->rowCount() > 0) {
        echo json_encode(['success' => false, 'message' => 'IP already blocked']);
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO blocked_ips (ip, user_id, website_id, reason, created_at, expiry_time)
        VALUES (?, ?, ?, ?, NOW(), '00:00:00')
    ");
    $stmt->execute([$ip, $userId, $websiteId, $reason]);
    
    echo json_encode(['success' => true, 'message' => "IP {$ip} blocked successfully"]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}