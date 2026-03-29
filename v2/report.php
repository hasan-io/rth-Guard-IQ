<?php
/**
 * Guard IQ — report.php
 * Public attack report page — no login required
 * Access: /report.php?token=<64-char-token>
 */

require_once __DIR__ . '/includes/db.php';

$token = trim($_GET['token'] ?? '');

// Token validate karo
if (empty($token) || strlen($token) !== 64 || !ctype_xdigit($token)) {
    $error = "Invalid or missing report token.";
} else {
    try {
        global $pdo;
        $stmt = $pdo->prepare("
            SELECT
                al.*,
                w.site_name,
                w.domain,
                u.email     AS owner_email,
                u.full_name AS owner_name
            FROM attack_logs al
            JOIN websites w ON al.website_id = w.id
            JOIN users    u ON al.user_id    = u.id
            WHERE al.report_token = ?
            LIMIT 1
        ");
        $stmt->execute([$token]);
        $report = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$report) {
            $error = "Report not found. The link may be invalid or expired.";
        }
    } catch (Exception $e) {
        $error = "Database error. Please try again later.";
        error_log("Guard IQ report.php error: " . $e->getMessage());
    }
}

// Severity styling
$severity_map = [
    'CRITICAL' => ['color' => '#ff2d2d', 'bg' => 'rgba(255,45,45,0.12)', 'icon' => '🔴'],
    'HIGH'     => ['color' => '#ff6b35', 'bg' => 'rgba(255,107,53,0.12)', 'icon' => '🟠'],
    'MEDIUM'   => ['color' => '#ffa500', 'bg' => 'rgba(255,165,0,0.12)',  'icon' => '🟡'],
    'LOW'      => ['color' => '#4caf50', 'bg' => 'rgba(76,175,80,0.12)',  'icon' => '🟢'],
];

$sev       = strtoupper($report['severity'] ?? 'HIGH');
$sev_style = $severity_map[$sev] ?? $severity_map['HIGH'];

// Attack type → icon
$type_icons = [
    'XSS'               => '💉',
    'SQL Injection'     => '🗄️',
    'SQLi'              => '🗄️',
    'Path Traversal'    => '📁',
    'Command Injection' => '💻',
];
$attack_icon = $type_icons[$report['attack_type'] ?? ''] ?? '⚡';

// Format payload safely
$payload_display = htmlspecialchars($report['attack_payload'] ?? 'Not captured');
$url_display     = htmlspecialchars($report['request_url']    ?? 'Not available');
$ua_display      = htmlspecialchars($report['user_agent']     ?? 'Unknown');
$ip_display      = htmlspecialchars($report['ip_address']     ?? 'Unknown');
$ts_display      = isset($report['timestamp'])
    ? date('D, d M Y — H:i:s T', strtotime($report['timestamp']))
    : 'Unknown';

$site_display  = htmlspecialchars($report['site_name'] ?? 'Unknown Site');
$type_display  = htmlspecialchars($report['attack_type'] ?? 'Unknown');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Guard IQ — Attack Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base:     #06060e;
      --bg-card:     #0c0c1a;
      --bg-deep:     #080814;
      --border:      #1a1a30;
      --border-glow: rgba(74,158,255,0.2);
      --text-main:   #e8e8f0;
      --text-muted:  #5a5a80;
      --text-dim:    #303050;
      --accent:      #4a9eff;
      --sev-color:   <?= $sev_style['color'] ?>;
      --sev-bg:      <?= $sev_style['bg'] ?>;
      --font-mono:   'JetBrains Mono', monospace;
      --font-disp:   'Syne', sans-serif;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-mono);
      font-size: 14px;
      min-height: 100vh;
      line-height: 1.6;
    }

    /* Scanline + grid background */
    body::before {
      content: '';
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background:
        repeating-linear-gradient(
          0deg,
          transparent,
          transparent 2px,
          rgba(74,158,255,0.015) 2px,
          rgba(74,158,255,0.015) 4px
        ),
        radial-gradient(ellipse 80% 60% at 50% -10%, rgba(74,158,255,0.07) 0%, transparent 70%);
    }

    .page-wrap {
      position: relative; z-index: 1;
      max-width: 860px;
      margin: 0 auto;
      padding: 40px 20px 80px;
    }

    /* ── TOP BAR ── */
    .alert-bar {
      background: var(--sev-color);
      color: #000;
      text-align: center;
      padding: 8px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 4px;
      text-transform: uppercase;
      border-radius: 6px 6px 0 0;
      animation: pulse-bar 2s ease-in-out infinite;
    }
    @keyframes pulse-bar {
      0%,100% { opacity: 1; }
      50%      { opacity: 0.75; }
    }

    /* ── MAIN CARD ── */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-top: none;
      border-radius: 0 0 12px 12px;
      overflow: hidden;
      box-shadow:
        0 0 0 1px rgba(74,158,255,0.05),
        0 40px 80px rgba(0,0,0,0.6),
        inset 0 1px 0 rgba(255,255,255,0.03);
    }

    /* ── HEADER ── */
    .report-header {
      padding: 32px 36px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: flex-start;
      gap: 20px;
    }
    .threat-badge {
      flex-shrink: 0;
      width: 56px; height: 56px;
      background: var(--sev-bg);
      border: 1px solid var(--sev-color);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 24px;
      box-shadow: 0 0 20px var(--sev-bg);
    }
    .report-title-block .label {
      font-size: 10px;
      letter-spacing: 4px;
      color: var(--accent);
      text-transform: uppercase;
      margin-bottom: 6px;
    }
    .report-title-block h1 {
      font-family: var(--font-disp);
      font-size: clamp(18px, 4vw, 26px);
      font-weight: 800;
      color: #fff;
      line-height: 1.2;
    }
    .report-title-block h1 span { color: var(--sev-color); }
    .report-id {
      margin-top: 8px;
      font-size: 11px;
      color: var(--text-muted);
      letter-spacing: 1px;
    }

    /* ── SEVERITY BADGE ── */
    .sev-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--sev-bg);
      border: 1px solid var(--sev-color);
      color: var(--sev-color);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 3px;
      text-transform: uppercase;
      padding: 4px 14px;
      border-radius: 100px;
      margin-top: 10px;
    }

    /* ── SECTION ── */
    .section {
      padding: 28px 36px;
      border-bottom: 1px solid var(--border);
    }
    .section:last-child { border-bottom: none; }
    .section-title {
      font-size: 10px;
      letter-spacing: 3px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-title::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }

    /* ── DETAILS GRID ── */
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 12px;
    }
    .detail-item {
      background: var(--bg-deep);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      transition: border-color 0.2s;
    }
    .detail-item:hover { border-color: rgba(74,158,255,0.25); }
    .detail-label {
      font-size: 10px;
      letter-spacing: 2px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 6px;
    }
    .detail-value {
      font-size: 14px;
      color: var(--text-main);
      word-break: break-all;
    }
    .detail-value.highlight { color: var(--sev-color); font-weight: 700; }
    .detail-value.accent-val { color: var(--accent); }

    /* ── CODE BLOCK ── */
    .code-block {
      background: var(--bg-deep);
      border: 1px solid var(--border);
      border-left: 3px solid var(--sev-color);
      border-radius: 8px;
      padding: 16px 20px;
      font-size: 13px;
      color: var(--sev-color);
      word-break: break-all;
      white-space: pre-wrap;
      line-height: 1.6;
      position: relative;
    }
    .code-block::before {
      content: 'PAYLOAD';
      position: absolute;
      top: -1px; right: 12px;
      font-size: 9px;
      letter-spacing: 2px;
      color: var(--text-dim);
      background: var(--bg-deep);
      padding: 0 6px;
    }

    /* ── URL BLOCK ── */
    .url-block {
      background: var(--bg-deep);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      font-size: 12px;
      color: var(--text-muted);
      word-break: break-all;
      margin-top: 12px;
    }
    .url-block strong { color: var(--text-main); }

    /* ── STATUS BANNER ── */
    .status-banner {
      display: flex;
      align-items: center;
      gap: 14px;
      background: rgba(74,255,120,0.06);
      border: 1px solid rgba(74,255,120,0.2);
      border-radius: 8px;
      padding: 16px 20px;
    }
    .status-dot {
      width: 10px; height: 10px;
      background: #4cff78;
      border-radius: 50%;
      box-shadow: 0 0 8px #4cff78;
      animation: blink 1.5s ease-in-out infinite;
      flex-shrink: 0;
    }
    @keyframes blink {
      0%,100% { opacity: 1; }
      50%      { opacity: 0.3; }
    }
    .status-text { color: #4cff78; font-size: 13px; }
    .status-text span { color: var(--text-muted); font-size: 12px; display: block; margin-top: 2px; }

    /* ── FOOTER ── */
    .report-footer {
      padding: 20px 36px;
      text-align: center;
      border-top: 1px solid var(--border);
    }
    .footer-logo {
      font-family: var(--font-disp);
      font-size: 13px;
      font-weight: 800;
      color: var(--text-dim);
      letter-spacing: 2px;
    }
    .footer-logo span { color: var(--accent); }
    .footer-sub {
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 4px;
    }

    /* ── ERROR PAGE ── */
    .error-wrap {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 40px 20px;
    }
    .error-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 48px 40px;
      max-width: 440px;
    }
    .error-icon { font-size: 48px; margin-bottom: 20px; }
    .error-title {
      font-family: var(--font-disp);
      font-size: 22px;
      font-weight: 800;
      color: #fff;
      margin-bottom: 12px;
    }
    .error-msg { color: var(--text-muted); font-size: 13px; }

    /* ── MOBILE ── */
    @media (max-width: 600px) {
      .page-wrap { padding: 20px 12px 60px; }
      .report-header { padding: 24px 20px; flex-direction: column; }
      .section { padding: 24px 20px; }
      .detail-grid { grid-template-columns: 1fr; }
      .report-footer { padding: 16px 20px; }
    }

    /* Entrance animation */
    .card { animation: fadeUp 0.5s ease both; }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(16px); }
      to   { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>

<?php if (isset($error)): ?>
<!-- ERROR STATE -->
<div class="error-wrap">
  <div class="error-card">
    <div class="error-icon">🔒</div>
    <div class="error-title">Report Not Found</div>
    <div class="error-msg"><?= htmlspecialchars($error) ?></div>
  </div>
</div>

<?php else: ?>
<!-- REPORT PAGE -->
<div class="page-wrap">

  <div class="alert-bar">
    <?= $sev_style['icon'] ?> &nbsp; <?= $sev ?> SEVERITY ATTACK REPORT &nbsp; <?= $sev_style['icon'] ?>
  </div>

  <div class="card">

    <!-- Header -->
    <div class="report-header">
      <div class="threat-badge"><?= $attack_icon ?></div>
      <div class="report-title-block">
        <div class="label">Guard IQ Security · Threat Report</div>
        <h1>Attack Detected on<br><span><?= $site_display ?></span></h1>
        <div class="report-id">REPORT #<?= strtoupper(substr($token, 0, 8)) ?> · <?= $ts_display ?></div>
        <div class="sev-pill">
          <?= $sev_style['icon'] ?> <?= $sev ?> Severity
        </div>
      </div>
    </div>

    <!-- Status -->
    <div class="section">
      <div class="status-banner">
        <div class="status-dot"></div>
        <div class="status-text">
          Attack Captured &amp; Logged
          <span>This attack has been recorded in the Guard IQ database. No action needed — for your review only.</span>
        </div>
      </div>
    </div>

    <!-- Attack Summary -->
    <div class="section">
      <div class="section-title">Attack Summary</div>
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">Attack Type</div>
          <div class="detail-value highlight"><?= $attack_icon ?> <?= $type_display ?></div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Severity</div>
          <div class="detail-value highlight"><?= $sev ?></div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Target Website</div>
          <div class="detail-value accent-val"><?= $site_display ?></div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Detected At</div>
          <div class="detail-value"><?= $ts_display ?></div>
        </div>
      </div>
    </div>

    <!-- Attacker Details -->
    <div class="section">
      <div class="section-title">Attacker Details</div>
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">IP Address</div>
          <div class="detail-value highlight"><?= $ip_display ?></div>
        </div>
        <div class="detail-item">
          <div class="detail-label">User Agent</div>
          <div class="detail-value"><?= $ua_display ?></div>
        </div>
        <?php if (!empty($report['country'])): ?>
        <div class="detail-item">
          <div class="detail-label">Origin Country</div>
          <div class="detail-value"><?= htmlspecialchars($report['country']) ?></div>
        </div>
        <?php endif; ?>
        <?php if (!empty($report['city'])): ?>
        <div class="detail-item">
          <div class="detail-label">City</div>
          <div class="detail-value"><?= htmlspecialchars($report['city']) ?></div>
        </div>
        <?php endif; ?>
        <?php if (!empty($report['isp'])): ?>
        <div class="detail-item">
          <div class="detail-label">ISP / Organization</div>
          <div class="detail-value"><?= htmlspecialchars($report['isp']) ?></div>
        </div>
        <?php endif; ?>
        <?php if (isset($report['is_vpn'])): ?>
        <div class="detail-item">
          <div class="detail-label">VPN / Proxy</div>
          <div class="detail-value <?= $report['is_vpn'] ? 'highlight' : '' ?>">
            <?= $report['is_vpn'] ? '⚠ VPN Detected' : 'Not detected' ?>
          </div>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Attack Payload -->
    <div class="section">
      <div class="section-title">Attack Payload</div>
      <div class="code-block"><?= $payload_display ?></div>
      <div class="url-block">
        <strong>Target URL:</strong> <?= $url_display ?>
      </div>
    </div>

    <!-- Footer -->
    <div class="report-footer">
      <div class="footer-logo"><span>Guard</span> IQ</div>
      <div class="footer-sub">Automated Security Report · Generated by Guard IQ · Not for public distribution</div>
    </div>

  </div>
</div>
<?php endif; ?>

</body>
</html>