<?php
require_once 'config.php';

$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verificarCSRF();
    
    $username = filter_input(INPUT_POST, 'username', FILTER_UNSAFE_RAW);
    $username = trim($username);
    $password = $_POST['password'] ?? '';

    if (empty($username) || empty($password)) {
        $message = "Todos os campos são obrigatórios.";
        $message_type = "danger";
    } elseif (strlen($username) < 3 || strlen($username) > 20) {
        $message = "O usuário deve ter entre 3 e 20 caracteres.";
        $message_type = "danger";
    } elseif (strlen($password) < 8) {
        $message = "A senha deve ter no mínimo 8 caracteres.";
        $message_type = "danger";
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            
            if ($stmt->fetch()) {
                $message = "Este nome de usuário já está registrado.";
                $message_type = "danger";
            } else {
                // UPDATE: Hash com fator de custo elevado para escalabilidade/segurança
                $options = ['cost' => 12];
                $hashed_password = password_hash($password, PASSWORD_BCRYPT, $options);
                
                $insert = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                $insert->execute([$username, $hashed_password]);
                
                $message = "Registro concluído com sucesso. Você pode entrar agora.";
                $message_type = "success";
            }
        } catch (\PDOException $e) {
            $message = "Erro ao processar requisição.";
            $message_type = "danger";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>REGISTRO // SYSTEM</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-container">
        <h2>Criar Conta</h2>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-<?= $message_type ?>"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <form action="register.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            
            <div class="form-group">
                <label for="username">Usuário (ID)</label>
                <input type="text" id="username" name="username" required autocomplete="off">
            </div>
            
            <div class="form-group">
                <label for="password">Senha de Acesso</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Registrar Terminal</button>
        </form>
        
        <a href="login.php" class="nav-link">Já possui registro? Autenticar-se →</a>
    </div>
</body>
</html>