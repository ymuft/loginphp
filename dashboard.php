<?php
require_once 'config.php';

// Bloqueio estrito contra acesso não autorizado
if (!isset($_SESSION['user_id']) || !isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// XSS Mitigation: Sanitização rigorosa na saída de dados dinâmicos do usuário
$username_limpo = htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>PAINEL DE CONTROLE // SYSTEM</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="dashboard-container">
        <h1>Painel Operacional</h1>
        <p style="margin-bottom: 20px;">Bem-vindo, Operador: <strong><?= $username_limpo ?></strong></p>
        
        <div style="background: #f0f0f0; padding: 20px; border: 1px solid #ccc; font-family: monospace; font-size: 0.9rem;">
            [RELATÓRIO DE SISTEMA SECURE-CORE v1.0]<br>
            Status: OPERACIONAL // SESSÃO ENCRIPTADA ATIVA.<br>
            Proteções Ativas: Anti-SQLi (PDO), Anti-XSS (Output Escaping), Anti-CSRF (Tokens Estritos).
        </div>

        <div class="system-status">
            <span>Zona Protegida. Log de atividade registrado sob o ID interno #<?= htmlspecialchars($_SESSION['user_id']) ?>.</span>
            <br><br>
            <a href="logout.php" style="color: var(--error); font-weight: bold; text-decoration: none;">[ LOGOUT / ENCERRAR SESSÃO ]</a>
        </div>
    </div>
</body>
</html>