<?php
require_once 'config.php';

// ── Verificação de sessão ──────────────────────────────────────
if (!isset($_SESSION['user_id']) || !isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// [SEGURANÇA] Session timeout de inatividade (30 minutos)
$timeout_inatividade = 30 * 60;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout_inatividade) {
    session_unset();
    session_destroy();
    header("Location: login.php?reason=timeout");
    exit;
}
$_SESSION['last_activity'] = time();

// [SEGURANÇA] IP binding — detecta session hijacking por mudança de IP
if (isset($_SESSION['ip_lock']) && $_SESSION['ip_lock'] !== $_SERVER['REMOTE_ADDR']) {
    error_log('[SECURITY] Session IP mismatch for user_id=' . $_SESSION['user_id']);
    session_unset();
    session_destroy();
    header("Location: login.php?reason=security");
    exit;
}

$username_limpo = htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8');
$user_id_limpo  = htmlspecialchars($_SESSION['user_id'], ENT_QUOTES, 'UTF-8');
$hora_atual     = date('H:i:s');
$data_atual     = date('d/m/Y');

// Nonce para CSP
$csp_nonce = base64_encode(random_bytes(16));
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self' 'nonce-<?= $csp_nonce ?>'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none';">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <!-- [SEGURANÇA] Impede que a página seja exibida em frames (Clickjacking) -->
    <meta http-equiv="X-Frame-Options" content="DENY">
    <!-- [SEGURANÇA] Impede o cache de páginas autenticadas -->
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
    <meta http-equiv="Pragma" content="no-cache">
    <title>Painel Operacional — MES System</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="bg-scene" aria-hidden="true">
    <div class="bg-blob bg-blob-1"></div>
    <div class="bg-blob bg-blob-2"></div>
    <div class="bg-blob bg-blob-3"></div>
</div>

<div class="dashboard-wrapper">
    <div class="dashboard-card">

        <!-- Header -->
        <div class="dashboard-header">
            <div class="dashboard-brand">
                <div class="brand-icon">
                    <svg viewBox="0 0 24 24" style="width:20px;height:20px;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;">
                        <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
                    </svg>
                </div>
                <div class="brand-meta">
                    <span class="brand-name">MES System</span>
                    <span class="brand-sub">Painel Operacional</span>
                </div>
            </div>

            <a href="logout.php" class="logout-btn">
                <svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Encerrar Sessão
            </a>
        </div>

        <!-- Body -->
        <div class="dashboard-body">

            <p class="dash-greeting">
                Bem-vindo, <span><?= $username_limpo ?></span>
            </p>
            <p class="dash-meta">
                Sessão iniciada em <?= $data_atual ?> · <?= $hora_atual ?> · ID interno #<?= $user_id_limpo ?>
            </p>

            <!-- Status Grid -->
            <div class="status-grid">
                <div class="status-card">
                    <div class="status-icon blue">
                        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <div class="status-info">
                        <h4>Anti-SQLi</h4>
                        <p>PDO Ativo</p>
                        <small>Prepared Statements reais</small>
                    </div>
                </div>

                <div class="status-card">
                    <div class="status-icon indigo">
                        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
                    </div>
                    <div class="status-info">
                        <h4>Anti-XSS</h4>
                        <p>CSP + Escaping</p>
                        <small>Output sanitizado</small>
                    </div>
                </div>

                <div class="status-card">
                    <div class="status-icon green">
                        <svg viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
                    </div>
                    <div class="status-info">
                        <h4>Anti-CSRF</h4>
                        <p>Token Ativo</p>
                        <small>Validação estrita por request</small>
                    </div>
                </div>
            </div>

            <!-- Terminal Block -->
            <div class="terminal-block">
                <div class="terminal-line">
                    <span class="t-key">SECURE-CORE</span>
                    <span class="t-sep">//</span>
                    <span class="t-val">v2.0</span>
                </div>
                <div class="terminal-line">
                    <span class="t-key">STATUS</span>
                    <span class="t-sep">&gt;&gt;</span>
                    <span class="t-ok">OPERACIONAL</span>
                </div>
                <div class="terminal-line">
                    <span class="t-key">SESSION</span>
                    <span class="t-sep">&gt;&gt;</span>
                    <span class="t-val">ENCRYPTED · STRICT · IP-BOUND</span>
                </div>
                <div class="terminal-line">
                    <span class="t-key">TIMEOUT</span>
                    <span class="t-sep">&gt;&gt;</span>
                    <span class="t-warn">30 MIN INATIVIDADE</span>
                </div>
                <div class="terminal-line">
                    <span class="t-key">BRUTE FORCE</span>
                    <span class="t-sep">&gt;&gt;</span>
                    <span class="t-ok">PROTEGIDO (5 TENTATIVAS / 15 MIN)</span>
                </div>
                <div class="terminal-line">
                    <span class="t-key">OPERATOR</span>
                    <span class="t-sep">&gt;&gt;</span>
                    <span class="t-val"><?= $username_limpo ?> [#<?= $user_id_limpo ?>]</span>
                </div>
            </div>

        </div><!-- /dashboard-body -->
    </div><!-- /dashboard-card -->
</div>

<script>
// Atualiza hora em tempo real no painel
// (sem reload de página — mantém sessão)
</script>
</body>
</html>