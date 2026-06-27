<?php
require_once 'config.php';

// Redireciona usuário já autenticado
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}

$csp_nonce = base64_encode(random_bytes(16));
$error = '';
$bloqueado = false;
$segundos_restantes = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verificarCSRF();

    $max_tentativas  = 5;
    $janela_bloqueio = 15 * 60;
    $ip_usuario      = $_SERVER['REMOTE_ADDR'];
    $tempo_atual     = time();
    $tempo_limite    = $tempo_atual - $janela_bloqueio;

    try {
        $stmt_check = $pdo->prepare(
            "SELECT COUNT(id) as total, MAX(attempt_time) as last_attempt
             FROM login_attempts
             WHERE ip_address = ? AND attempt_time > ?"
        );
        $stmt_check->execute([$ip_usuario, $tempo_limite]);
        $resultado  = $stmt_check->fetch();
        $tentativas = (int) $resultado['total'];

        if ($tentativas >= $max_tentativas) {
            $segundos_restantes = max(0, $janela_bloqueio - ($tempo_atual - (int)$resultado['last_attempt']));
            http_response_code(429);
            $error     = "Múltiplas tentativas detectadas. Aguarde antes de tentar novamente.";
            $bloqueado = true;
        } else {
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            if (empty($username) || empty($password)) {
                $error = "Preencha todos os campos de acesso.";
            } elseif (strlen($username) > 60) {
                $error = "Entrada inválida.";
            } else {
                // FIX: removido is_active da query — coluna pode não existir na tabela
                $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();

                // Timing-safe: roda password_verify mesmo sem usuário (evita user enumeration)
                $dummy_hash = '$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
                $hash_check = $user ? $user['password'] : $dummy_hash;
                $senha_ok   = password_verify($password, $hash_check);

                if ($user && $senha_ok) {
                    $pdo->prepare("DELETE FROM login_attempts WHERE ip_address = ?")->execute([$ip_usuario]);
                    session_regenerate_id(true);
                    $_SESSION['user_id']       = $user['id'];
                    $_SESSION['username']      = $user['username'];
                    $_SESSION['last_activity'] = $tempo_atual;
                    $_SESSION['ip_lock']       = $ip_usuario;
                    header("Location: dashboard.php");
                    exit;
                } else {
                    $pdo->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, ?)")
                        ->execute([$ip_usuario, $tempo_atual]);
                    $restantes = max(0, $max_tentativas - $tentativas - 1);
                    $error = "Credenciais inválidas." . ($restantes > 0 ? " Tentativas restantes: {$restantes}." : "");
                }
            }
        }
    } catch (\PDOException $e) {
        error_log('[LOGIN] DB Error: ' . $e->getMessage());
        $error = "Erro no servidor de autenticação. Tente novamente.";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <title>Autenticação — MES System</title>
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

<div class="auth-wrapper">
    <div class="auth-card">

        <div class="brand-header">
            <div class="brand-icon">
                <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
            </div>
            <div class="brand-meta">
                <span class="brand-name">MES System</span>
                <span class="brand-sub">Manufacturing Execution</span>
            </div>
        </div>

        <h1 class="auth-title">Acesso ao Sistema</h1>
        <p class="auth-subtitle">Insira suas credenciais para iniciar uma sessão segura.</p>

        <?php if (!empty($error)): ?>
            <div class="alert <?= $bloqueado ? 'alert-warning' : 'alert-danger' ?>">
                <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <?= htmlspecialchars($error) ?>
            </div>
            <?php if ($bloqueado && $segundos_restantes > 0): ?>
                <div class="lockout-timer">
                    Aguarde <span id="countdown"><?= gmdate('i:s', $segundos_restantes) ?></span> para nova tentativa.
                </div>
            <?php endif; ?>
        <?php endif; ?>

        <form action="login.php" method="POST" id="loginForm">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

            

            <div class="form-group">
                <label for="username">Usuário</label>
                <div class="input-wrapper">
                    <span class="input-icon">
                        <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    <input type="text" id="username" name="username"
                           placeholder="Digite seu usuário"
                           maxlength="60"
                           <?= $bloqueado ? 'disabled' : '' ?>
                           required>
                </div>
            </div>

            <div class="form-group">
                <label for="password">Senha</label>
                <div class="input-wrapper">
                    <span class="input-icon">
                        <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </span>
                    <input type="password" id="password" name="password"
                           placeholder="••••••••"
                           maxlength="128"
                           <?= $bloqueado ? 'disabled' : '' ?>
                           required>
                    <button type="button" class="toggle-pw" id="togglePw" aria-label="Mostrar senha">
                        <svg id="eyeIcon" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                </div>
            </div>

            <button type="submit" class="btn-primary" <?= $bloqueado ? 'disabled' : '' ?>>
                <svg viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                Acessar Sistema
            </button>
        </form>

        <div class="auth-footer">
            Não possui acesso? <a href="register.php">Solicitar credenciais →</a>
        </div>

        <div class="security-badge">
            <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Conexão protegida · PDO · CSRF · Anti-Brute Force
        </div>
    </div>

<script>
// Toggle visibilidade da senha
const toggleBtn = document.getElementById('togglePw');
const pwInput   = document.getElementById('password');
const eyeIcon   = document.getElementById('eyeIcon');
const eyeOpen   = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
const eyeClosed = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
toggleBtn.addEventListener('click', function() {
    var isText = pwInput.type === 'text';
    pwInput.type = isText ? 'password' : 'text';
    eyeIcon.innerHTML = isText ? eyeOpen : eyeClosed;
});

// Countdown de bloqueio
var countdownEl = document.getElementById('countdown');
if (countdownEl) {
    var parts = countdownEl.textContent.split(':');
    var total = parseInt(parts[0]) * 60 + parseInt(parts[1]);
    var tick = setInterval(function() {
        total--;
        if (total <= 0) { clearInterval(tick); location.reload(); return; }
        var m = String(Math.floor(total / 60)).padStart(2, '0');
        var s = String(total % 60).padStart(2, '0');
        countdownEl.textContent = m + ':' + s;
    }, 1000);
}
</script>
</body>
</html>