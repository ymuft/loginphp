<?php
require_once 'config.php';

// ── Logout Seguro ─────────────────────────────────────────────

// [SEGURANÇA] Registra o logout antes de destruir a sessão
if (isset($_SESSION['user_id'])) {
    error_log('[LOGOUT] User #' . $_SESSION['user_id'] . ' encerrou sessão. IP: ' . $_SERVER['REMOTE_ADDR']);
}

// Limpa todas as variáveis da sessão
$_SESSION = [];

// [SEGURANÇA] Destroi o cookie de sessão no navegador
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(), '',
        time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

// Destroi a sessão no servidor
session_destroy();

// [SEGURANÇA] Cabeçalhos para evitar cache da página protegida após logout
header("Cache-Control: no-store, no-cache, must-revalidate, private");
header("Pragma: no-cache");

// Redireciona para login
header("Location: login.php");
exit;