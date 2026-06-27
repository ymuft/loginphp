<?php
require_once 'config.php';

if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}

$error = '';
$bloqueado = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verificarCSRF();

    // Configurações Anti-Brute Force
    $max_tentativas = 5;
    $janela_bloqueio = 15 * 60; // 15 minutos
    $ip_usuario = $_SERVER['REMOTE_ADDR'];
    $tempo_atual = time();
    $tempo_limite = $tempo_atual - $janela_bloqueio;

    try {
        // 1. Verifica se o IP excedeu as tentativas
        $stmt_check = $pdo->prepare("SELECT COUNT(id) FROM login_attempts WHERE ip_address = ? AND attempt_time > ?");
        $stmt_check->execute([$ip_usuario, $tempo_limite]);
        $tentativas = $stmt_check->fetchColumn();

        if ($tentativas >= $max_tentativas) {
            http_response_code(429);
            $error = "Múltiplas tentativas falhas. Terminal suspenso temporariamente. Aguarde 15 minutos.";
            $bloqueado = true;
        } else {
            // 2. Fluxo de Login Seguro
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            if (!empty($username) && !empty($password)) {
                $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();

                if ($user && password_verify($password, $user['password'])) {
                    // SUCESSO: Limpa o histórico de falhas do IP
                    $stmt_clear = $pdo->prepare("DELETE FROM login_attempts WHERE ip_address = ?");
                    $stmt_clear->execute([$ip_usuario]);

                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['last_activity'] = time();
                    
                    header("Location: dashboard.php");
                    exit;
                } else {
                    // FALHA: Registra a tentativa
                    $stmt_fail = $pdo->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, ?)");
                    $stmt_fail->execute([$ip_usuario, $tempo_atual]);
                    
                    $tentativas_restantes = $max_tentativas - $tentativas - 1;
                    $error = "Credenciais inválidas. Tentativas restantes: " . $tentativas_restantes;
                }
            } else {
                $error = "Preencha todos os campos.";
            }
        }
    } catch (\PDOException $e) {
        $error = "Erro no servidor de autenticação.";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>AUTENTICAÇÃO // SYSTEM</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-container">
        <h2>Autenticação</h2>
        
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form action="login.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            
            <div class="form-group">
                <label for="username">Usuário</label>
                <input type="text" id="username" name="username" required <?= $bloqueado ? 'disabled' : '' ?>>
            </div>
            
            <div class="form-group">
                <label for="password">Senha</label>
                <input type="password" id="password" name="password" required <?= $bloqueado ? 'disabled' : '' ?>>
            </div>
            
            <button type="submit" <?= $bloqueado ? 'disabled style="background:#ccc; cursor:not-allowed;"' : '' ?>>
                Acessar Sistema
            </button>
        </form>
        
        <a href="register.php" class="nav-link">Solicitar novo acesso terminal →</a>
    </div>
</body>
</html>