<?php
session_start();
require_once '../includes/db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false]);
    exit;
}

$userId = $_SESSION['user_id'];
$websiteId = $_SESSION['website_id'] ?? 1;
$lastId = intval($_GET['last_id'] ?? 0);

try {
    $stmt = $pdo->prepare("
        SELECT id, attack_type, severity, ip_address, timestamp
        FROM attack_logs
        WHERE user_id = ? AND website_id = ? AND id > ?
        ORDER BY id DESC
        LIMIT 1
    ");
    $stmt->execute([$userId, $websiteId, $lastId]);
    $attack = $stmt->fetch();

    if ($attack) {
        echo json_encode([
            'success' => true,
            'new_attack' => true,
            'id' => $attack['id'],
            'attack_type' => $attack['attack_type'],
            'severity' => $attack['severity'],
            'ip' => $attack['ip_address'],
            'time' => date('H:i:s', strtotime($attack['timestamp']))
        ]);
    } else {
        echo json_encode(['success' => true, 'new_attack' => false]);
    }
} catch (Exception $e) {
    echo json_encode(['success' => false]);
}