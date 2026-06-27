<?php
// Configurações de endurecimento de sessão (Mitigação de Session Hijacking)
ini_set('session.cookie_httponly', 1); // Impede acesso via JavaScript (XSS)
ini_set('session.cookie_use_only_cookies', 1); // Força uso apenas de cookies
ini_set('session.use_strict_mode', 1); // Previne Session Fixation

// Se estiver usando HTTPS em produção, descomente a linha abaixo:
// ini_set('session.cookie_secure', 1); 

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Conexão Segura com Banco de Dados (PDO)
$host = 'localhost';
$db   = 'mes';
$user = 'MES'; // Altere para seu usuário de produção
$pass = 'fcRb7XLW2nbDBRs3';     // Altere para sua senha de produção
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // Lança exceções em erros
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       // Array associativo por padrão
    PDO::ATTR_EMULATE_PREPARES   => false,                  // Desativa emulação para garantir Prepared Statements reais
];

try {
     $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
     // Em produção, nunca exiba o $e->getMessage() diretamente (vazamento de informações)
     error_log($e->getMessage());
     die("Erro interno de comunicação com o servidor.");
}

// Mecanismo de Proteção Anti-CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function verificarCSRF() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            http_response_code(403);
            die("Falha na validação de segurança (CSRF Token inválido).");
        }
    }
}