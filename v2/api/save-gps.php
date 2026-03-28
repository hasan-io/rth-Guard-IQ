<?php
session_start();
require_once '../includes/db.php';

header('Content-Type: application/json');

$data = json_decode(file_get_contents('php://input'), true);

$gpsLat  = $data['gps_lat'] ?? null;
$gpsLng  = $data['gps_lng'] ?? null;
$gpsAcc  = $data['gps_accuracy'] ?? null;

if (!$gpsLat || !$gpsLng) {
    echo json_encode(['success' => false]);
    exit;
}

// Client IP get karo
$clientIp = $_SERVER['HTTP_CF_CONNECTING_IP']
    ?? $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['REMOTE_ADDR'];

if (str_contains($clientIp, ',')) {
    $clientIp = trim(explode(',', $clientIp)[0]);
}

try {
    // Latest log entry update karo is IP ki
    $stmt = $pdo->prepare("
        UPDATE logs 
        SET gps_latitude = ?,
            gps_longitude = ?,
            gps_accuracy = ?,
            location_source = 'gps'
        WHERE (ip = ? OR ip = '::1' OR ip = '127.0.0.1')
ORDER BY timestamp DESC
LIMIT 1
    ");
    $stmt->execute([$gpsLat, $gpsLng, $gpsAcc, $clientIp]);

    echo json_encode(['success' => true]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}