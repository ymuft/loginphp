<?php
require_once 'config.php';

$message      = '';
$message_type = '';

// [SEGURANÇA] Gera nonce CSP único por request
$csp_nonce = base64_encode(random_bytes(16));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verificarCSRF();

    // [SEGURANÇA] Honeypot — se preenchido, é bot
    if (!empty($_POST['website'])) {
        http_response_code(400);
        die();
    }

    $username = trim(filter_input(INPUT_POST, 'username', FILTER_UNSAFE_RAW) ?? '');
    $password = $_POST['password']         ?? '';
    $confirm  = $_POST['password_confirm'] ?? '';

    // ── Validações ─────────────────────────────────────────────
    if (empty($username) || empty($password) || empty($confirm)) {
        $message      = "Todos os campos são obrigatórios.";
        $message_type = "danger";
    } elseif (!preg_match('/^[a-zA-Z0-9_\-\.]{3,20}$/', $username)) {
        // [SEGURANÇA] Permite apenas caracteres seguros no username
        $message      = "O usuário deve ter 3–20 caracteres (letras, números, _ - .).";
        $message_type = "danger";
    } elseif ($password !== $confirm) {
        $message      = "As senhas não coincidem.";
        $message_type = "danger";
    } elseif (strlen($password) < 8) {
        $message      = "A senha deve ter no mínimo 8 caracteres.";
        $message_type = "danger";
    } elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password)) {
        // [SEGURANÇA] Força mínima de senha: ao menos 1 maiúscula e 1 número
        $message      = "A senha deve conter ao menos uma letra maiúscula e um número.";
        $message_type = "danger";
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);

            if ($stmt->fetch()) {
                // [SEGURANÇA] Mensagem genérica evita confirmação de usuários existentes em contextos mais sensíveis
                $message      = "Este nome de usuário não está disponível.";
                $message_type = "danger";
            } else {
                // [SEGURANÇA] bcrypt com custo 12 — resistente a brute force
                $hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

                $insert = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                $insert->execute([$username, $hashed]);

                $message      = "Conta criada com sucesso. Você já pode fazer login.";
                $message_type = "success";
            }
        } catch (\PDOException $e) {
            error_log('[REGISTER] DB Error: ' . $e->getMessage());
            $message      = "Erro ao processar o registro. Tente novamente.";
            $message_type = "danger";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self' 'nonce-<?= $csp_nonce ?>'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none';">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <title>Criar Conta — MES System</title>
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

        <!-- Brand -->
        <div class="brand-header">
            <div class="brand-icon">
                <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
            </div>
            <div class="brand-meta">
                <span class="brand-name">MES System</span>
                <span class="brand-sub">Manufacturing Execution</span>
            </div>
        </div>

        <h1 class="auth-title">Criar Credenciais</h1>
        <p class="auth-subtitle">Preencha os dados abaixo para solicitar acesso ao sistema.</p>

        <?php if (!empty($message)): ?>
            <div class="alert alert-<?= htmlspecialchars($message_type) ?>">
                <?php if ($message_type === 'danger'): ?>
                    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <?php else: ?>
                    <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                <?php endif; ?>
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <form action="register.php" method="POST" id="registerForm">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <!-- Honeypot -->
            <div class="hp-field"><input type="text" name="website" tabindex="-1" autocomplete="off"></div>

            <div class="form-group">
                <label for="username">Usuário</label>
                <div class="input-wrapper">
                    <span class="input-icon">
                        <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    <input type="text" id="username" name="username"
                           placeholder="ex: joao.silva"
                           maxlength="20"
                           pattern="[a-zA-Z0-9_\-\.]{3,20}"
                           title="3–20 caracteres: letras, números, _ - ."
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
                           placeholder="Mín. 8 caracteres"
                           maxlength="128"
                           required>
                    <button type="button" class="toggle-pw" id="togglePw" aria-label="Mostrar senha">
                        <svg id="eyeIcon" viewBox="0 0 24 24">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                    </button>
                </div>
                <!-- Barra de força de senha -->
                <div class="strength-bar-wrap" id="strengthBars">
                    <span id="bar1"></span>
                    <span id="bar2"></span>
                    <span id="bar3"></span>
                    <span id="bar4"></span>
                </div>
                <div class="strength-label" id="strengthLabel"></div>
            </div>

            <div class="form-group">
                <label for="password_confirm">Confirmar Senha</label>
                <div class="input-wrapper">
                    <span class="input-icon">
                        <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                    </span>
                    <input type="password" id="password_confirm" name="password_confirm"
                           placeholder="Repita a senha"
                           maxlength="128"
                           required>
                </div>
            </div>

            <button type="submit" class="btn-primary">
                <svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
                Criar Conta
            </button>
        </form>

        <div class="auth-footer">
            Já possui acesso? <a href="login.php">Fazer login →</a>
        </div>

        <div class="security-badge">
            <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Senha armazenada com bcrypt · Formulário protegido por CSRF
        </div>
    </div>
</div>

<script>
// ── Toggle senha ───────────────────────────────────────────────
const toggleBtn = document.getElementById('togglePw');
const pwInput   = document.getElementById('password');
const eyeIcon   = document.getElementById('eyeIcon');
const eyeOpen   = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
const eyeClosed = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;

toggleBtn.addEventListener('click', () => {
    const isText = pwInput.type === 'text';
    pwInput.type = isText ? 'password' : 'text';
    eyeIcon.innerHTML = isText ? eyeOpen : eyeClosed;
});

// ── Indicador de força de senha ───────────────────────────────
const bars  = [document.getElementById('bar1'), document.getElementById('bar2'),
               document.getElementById('bar3'), document.getElementById('bar4')];
const label = document.getElementById('strengthLabel');

const colors  = ['#ba1a1a', '#e65100', '#f9a825', '#1b5e20'];
const labels  = ['Muito fraca', 'Fraca', 'Média', 'Forte'];

function calcStrength(pw) {
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[0-9]/.test(pw)) score++;
    if (/[^a-zA-Z0-9]/.test(pw)) score++;
    return Math.min(score, 4);
}

pwInput.addEventListener('input', () => {
    const pw    = pwInput.value;
    const score = pw.length ? calcStrength(pw) : 0;
    bars.forEach((b, i) => {
        b.style.background = i < score ? colors[score - 1] : 'var(--outline-variant)';
    });
    label.textContent = pw.length ? labels[score - 1] : '';
    label.style.color = pw.length ? colors[score - 1] : 'var(--outline)';
});

// ── Previne double-submit ──────────────────────────────────────
document.getElementById('registerForm').addEventListener('submit', function() {
    const btn = this.querySelector('button[type="submit"]');
    setTimeout(() => {
        btn.disabled = true;
        btn.innerHTML = 'Criando conta...';
    }, 0);
});
</script>
</body>
</html>