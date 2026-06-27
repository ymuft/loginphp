<?php
// ============================================================
// CONFIG.PHP — MES SYSTEM — SECURE CORE v2.1
// ============================================================

// ── Cabeçalhos de Segurança HTTP ────────────────────────────
if (!headers_sent()) {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
    // header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"); // HTTPS prod
}

// ── Configurações de Sessão ──────────────────────────────────
ini_set('session.cookie_httponly', 1);   // Bloqueia acesso via JS (XSS)
ini_set('session.use_only_cookies', 1);  // Força uso apenas de cookies
ini_set('session.use_strict_mode', 1);   // Previne Session Fixation
ini_set('session.gc_maxlifetime', 1800); // Expira sessões após 30 min no servidor
// NOTA: cookie_samesite=Strict foi REMOVIDO propositalmente.
// Ele impede o envio do cookie em POSTs de formulário em certos contextos,
// quebrando a validação CSRF. 'Lax' é o padrão seguro adequado para este caso.
ini_set('session.cookie_samesite', 'Lax');
// ini_set('session.cookie_secure', 1); // Descomente em produção HTTPS

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── Expiração de sessão por inatividade (30 min) ─────────────
define('SESSION_TIMEOUT', 1800);
if (isset($_SESSION['last_activity']) &&
    (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    session_unset();
    session_destroy();
    session_start(); // Reinicia sessão limpa
}

// ── Conexão com Banco de Dados (PDO) ────────────────────────
$host    = 'localhost';
$db      = 'mes';
$user    = 'MES';
$pass    = 'fcRb7XLW2nbDBRs3'; // Em produção: use variável de ambiente
$charset = 'utf8mb4';

$dsn     = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_TIMEOUT            => 5,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    error_log('[CONFIG] DB Connection failed: ' . $e->getMessage());
    http_response_code(503);
    die("Serviço temporariamente indisponível. Tente novamente em instantes.");
}

// ── Token CSRF ───────────────────────────────────────────────
// Gera token forte uma vez por sessão — NÃO rotaciona por POST.
// A rotação por POST causava falha na segunda tentativa de login
// pois o HTML já havia sido renderizado com o token antigo.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Verifica o token CSRF em requisições POST.
 * Encerra a requisição com 403 se inválido.
 */
function verificarCSRF(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token_enviado = $_POST['csrf_token'] ?? '';
        $token_sessao  = $_SESSION['csrf_token'] ?? '';

        // hash_equals() previne timing attacks
        if (empty($token_enviado) || !hash_equals($token_sessao, $token_enviado)) {
            error_log('[CSRF] Token inválido. IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            http_response_code(403);
            die("Falha na validação de segurança. Recarregue a página e tente novamente.");
        }
        // Token válido — mantido na sessão para permitir tentativas repetidas
        // (ex: senha errada → nova tentativa sem recarregar)
    }
}