<?php
/**
 * API del Servidor de Licencias
 * Maneja validación, activación y verificación de licencias
 * Version: 1.0
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejar preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Configuración de la base de datos del servidor de licencias
$license_db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj', 
    'database' => 'serverbussn_sdcode'
];

class LicenseAPI {
    private $conn;
    private $api_version = '4.5';
    
    public function __construct($db_config) {
        $this->conn = new mysqli(
            $db_config['host'],
            $db_config['username'], 
            $db_config['password'],
            $db_config['database']
        );
        
        if ($this->conn->connect_error) {
            $this->sendError('Database connection failed', 500);
        }
        
        $this->conn->set_charset("utf8mb4");
    }
    
    public function handleRequest() {
    $method = $_SERVER['REQUEST_METHOD'];
    $action = $_GET['action'] ?? $_POST['action'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'];
        $action = $_GET['action'] ?? $_POST['action'] ?? '';
        
        // Log de la petición
        $this->logRequest($action);
        
        switch ($action) {
            case 'validate':
                $this->validateLicense();
                break;
            case 'activate':
                $this->activateLicense();
                break;
            case 'verify':
                $this->verifyLicense();
                break;
            case 'deactivate':
                $this->deactivateLicense();
                break;
            case 'status':
                $this->getStatus();
                break;
            default:
                $this->sendError('Invalid action', 400);
        }
    }
    
    private function validateLicense() {
        $license_key = $this->getParam('license_key');
        $domain = $this->getParam('domain');
        
        if (!$license_key || !$domain) {
            $this->sendError('Missing required parameters: license_key, domain', 400);
        }
        
        // Limpiar y validar el dominio
        $domain = $this->cleanDomain($domain);
        
        // Buscar la licencia
        $stmt = $this->conn->prepare("SELECT * FROM licenses WHERE license_key = ?");
        $stmt->bind_param("s", $license_key);
        $stmt->execute();
        $license = $stmt->get_result()->fetch_assoc();
        
        if (!$license) {
            $this->logActivity($license['id'] ?? null, null, 'validation', 'failure', 'License key not found');
            $this->sendError('Invalid license key', 404);
        }
        
        // Verificar estado de la licencia
        if ($license['status'] !== 'active') {
            $this->logActivity($license['id'], null, 'validation', 'failure', 'License not active: ' . $license['status']);
            $this->sendError('License is ' . $license['status'], 403);
        }
        
        // Verificar expiración
        if ($license['expires_at'] && strtotime($license['expires_at']) < time()) {
            $this->logActivity($license['id'], null, 'validation', 'failure', 'License expired');
            $this->sendError('License has expired', 403);
        }
        
        // Verificar límite de dominios
        $stmt = $this->conn->prepare("SELECT COUNT(*) as count FROM license_activations WHERE license_id = ? AND status = 'active' AND domain != ?");
        $stmt->bind_param("is", $license['id'], $domain);
        $stmt->execute();
        $activations = $stmt->get_result()->fetch_assoc();
        
        if ($activations['count'] >= $license['max_domains']) {
            // Verificar si este dominio ya está activado
            $stmt = $this->conn->prepare("SELECT id FROM license_activations WHERE license_id = ? AND domain = ? AND status = 'active'");
            $stmt->bind_param("is", $license['id'], $domain);
            $stmt->execute();
            $existing = $stmt->get_result()->fetch_assoc();
            
            if (!$existing) {
                $this->logActivity($license['id'], null, 'validation', 'failure', 'Domain limit exceeded');
                $this->sendError('Maximum domains limit reached', 403);
            }
        }
        
        $this->logActivity($license['id'], null, 'validation', 'success', 'License validated for domain: ' . $domain);
        
        $this->sendSuccess([
            'valid' => true,
            'license_info' => [
                'id' => $license['id'],
                'client_name' => $license['client_name'],
                'product_name' => $license['product_name'],
                'version' => $license['version'],
                'license_type' => $license['license_type'],
                'max_domains' => $license['max_domains'],
                'expires_at' => $license['expires_at'],
                'current_activations' => $activations['count']
            ]
        ]);
    }
    
    private function activateLicense() {
        $license_key = $this->getParam('license_key');
        $domain = $this->getParam('domain');
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $server_info = $this->getParam('server_info', []);
        
        if (!$license_key || !$domain) {
            $this->sendError('Missing required parameters: license_key, domain', 400);
        }
        
        $domain = $this->cleanDomain($domain);
        
        // Validar licencia primero
        $stmt = $this->conn->prepare("SELECT * FROM licenses WHERE license_key = ? AND status = 'active'");
        $stmt->bind_param("s", $license_key);
        $stmt->execute();
        $license = $stmt->get_result()->fetch_assoc();
        
        if (!$license) {
            $this->logActivity(null, null, 'activation', 'failure', 'Invalid license key for activation');
            $this->sendError('Invalid or inactive license key', 404);
        }
        
        // Verificar expiración
        if ($license['expires_at'] && strtotime($license['expires_at']) < time()) {
            $this->logActivity($license['id'], null, 'activation', 'failure', 'Attempted activation of expired license');
            $this->sendError('License has expired', 403);
        }
        
        // Verificar si ya está activado en este dominio
        $stmt = $this->conn->prepare("SELECT id FROM license_activations WHERE license_id = ? AND domain = ?");
        $stmt->bind_param("is", $license['id'], $domain);
        $stmt->execute();
        $existing = $stmt->get_result()->fetch_assoc();
        
        if ($existing) {
            // Actualizar información existente
            $stmt = $this->conn->prepare("UPDATE license_activations SET status = 'active', ip_address = ?, server_info = ?, last_check = NOW(), user_agent = ? WHERE id = ?");
            $stmt->bind_param("sssi", $ip_address, json_encode($server_info), $user_agent, $existing['id']);
            $stmt->execute();
            
            $this->logActivity($license['id'], $existing['id'], 'activation', 'success', 'License reactivated for domain: ' . $domain);
            
            $this->sendSuccess([
                'activated' => true,
                'message' => 'License reactivated successfully',
                'activation_id' => $existing['id']
            ]);
        }
        
        // Verificar límite de dominios
        $stmt = $this->conn->prepare("SELECT COUNT(*) as count FROM license_activations WHERE license_id = ? AND status = 'active'");
        $stmt->bind_param("i", $license['id']);
        $stmt->execute();
        $activations = $stmt->get_result()->fetch_assoc();
        
        if ($activations['count'] >= $license['max_domains']) {
            $this->logActivity($license['id'], null, 'activation', 'failure', 'Domain limit exceeded for activation');
            $this->sendError('Maximum domains limit reached', 403);
        }
        
        // Crear nueva activación
        $stmt = $this->conn->prepare("INSERT INTO license_activations (license_id, domain, ip_address, server_info, user_agent) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("issss", $license['id'], $domain, $ip_address, json_encode($server_info), $user_agent);
        
        if ($stmt->execute()) {
            $activation_id = $this->conn->insert_id;
            $this->logActivity($license['id'], $activation_id, 'activation', 'success', 'License activated for domain: ' . $domain);
            
            $this->sendSuccess([
                'activated' => true,
                'message' => 'License activated successfully',
                'activation_id' => $activation_id
            ]);
        } else {
            $this->logActivity($license['id'], null, 'activation', 'failure', 'Database error during activation');
            $this->sendError('Activation failed', 500);
        }
    }
    
    private function verifyLicense() {
        $license_key = $this->getParam('license_key');
        $domain = $this->getParam('domain');
        
        if (!$license_key || !$domain) {
            $this->sendError('Missing required parameters: license_key, domain', 400);
        }
        
        $domain = $this->cleanDomain($domain);
        
        // Buscar licencia y activación
        $stmt = $this->conn->prepare("
            SELECT l.*, la.id as activation_id, la.status as activation_status, la.check_count
            FROM licenses l
            LEFT JOIN license_activations la ON l.id = la.license_id AND la.domain = ?
            WHERE l.license_key = ?
        ");
        $stmt->bind_param("ss", $domain, $license_key);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if (!$result) {
            $this->logActivity(null, null, 'verification', 'failure', 'License not found for verification');
            $this->sendError('License not found', 404);
        }
        
        $license = $result;
        
        // Verificar estado de la licencia
        if ($license['status'] !== 'active') {
            $this->logActivity($license['id'], $license['activation_id'], 'verification', 'failure', 'License not active');
            $this->sendError('License is not active', 403);
        }
        
        // Verificar activación
        if (!$license['activation_id'] || $license['activation_status'] !== 'active') {
            $this->logActivity($license['id'], null, 'verification', 'failure', 'No active activation for domain');
            $this->sendError('License not activated for this domain', 403);
        }
        
        // Verificar expiración
        if ($license['expires_at'] && strtotime($license['expires_at']) < time()) {
            $this->logActivity($license['id'], $license['activation_id'], 'verification', 'failure', 'License expired');
            $this->sendError('License has expired', 403);
        }
        
        // Actualizar última verificación
        $stmt = $this->conn->prepare("UPDATE license_activations SET last_check = NOW(), check_count = check_count + 1 WHERE id = ?");
        $stmt->bind_param("i", $license['activation_id']);
        $stmt->execute();
        
        $this->logActivity($license['id'], $license['activation_id'], 'verification', 'success', 'License verified');
        
        $this->sendSuccess([
            'valid' => true,
            'license_status' => $license['status'],
            'expires_at' => $license['expires_at'],
            'check_count' => $license['check_count'] + 1,
            'next_check' => date('Y-m-d H:i:s', time() + (24 * 3600)) // 24 horas
        ]);
    }
    
    private function deactivateLicense() {
        $license_key = $this->getParam('license_key');
        $domain = $this->getParam('domain');
        
        if (!$license_key || !$domain) {
            $this->sendError('Missing required parameters: license_key, domain', 400);
        }
        
        $domain = $this->cleanDomain($domain);
        
        // Buscar activación
        $stmt = $this->conn->prepare("
            SELECT la.id, l.id as license_id
            FROM license_activations la
            JOIN licenses l ON la.license_id = l.id
            WHERE l.license_key = ? AND la.domain = ? AND la.status = 'active'
        ");
        $stmt->bind_param("ss", $license_key, $domain);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if (!$result) {
            $this->sendError('Active activation not found', 404);
        }
        
        // Desactivar
        $stmt = $this->conn->prepare("UPDATE license_activations SET status = 'inactive' WHERE id = ?");
        $stmt->bind_param("i", $result['id']);
        
        if ($stmt->execute()) {
            $this->logActivity($result['license_id'], $result['id'], 'deactivation', 'success', 'License deactivated for domain: ' . $domain);
            $this->sendSuccess(['deactivated' => true]);
        } else {
            $this->sendError('Deactivation failed', 500);
        }
    }
    
    private function getStatus() {
        $this->sendSuccess([
            'api_version' => $this->api_version,
            'status' => 'online',
            'timestamp' => date('Y-m-d H:i:s'),
            'server_time' => time()
        ]);
    }
    
    private function cleanDomain($domain) {
        // Remover protocolo
        $domain = preg_replace('#^https?://#', '', $domain);
        // Remover www.
        $domain = preg_replace('#^www\.#', '', $domain);
        // Remover puerto
        $domain = preg_replace('#:\d+$#', '', $domain);
        // Remover path
        $domain = explode('/', $domain)[0];
        // Convertir a minúsculas
        return strtolower(trim($domain));
    }
    
    private function getParam($key, $default = null) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $input = json_decode(file_get_contents('php://input'), true);
            return $input[$key] ?? $_POST[$key] ?? $default;
        }
        return $_GET[$key] ?? $default;
    }
    
    private function logRequest($action) {
        $data = [
            'method' => $_SERVER['REQUEST_METHOD'],
            'action' => $action,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'ip' => $_SERVER['REMOTE_ADDR'],
            'params' => $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET
        ];
        
        error_log("License API Request: " . json_encode($data));
    }
    
    private function logActivity($license_id, $activation_id, $action, $status, $message) {
        $stmt = $this->conn->prepare("
            INSERT INTO license_logs (license_id, activation_id, action, status, message, ip_address, user_agent, request_data) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_data = json_encode([
            'method' => $_SERVER['REQUEST_METHOD'],
            'params' => $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET
        ]);
        
        $stmt->bind_param("iissssss", $license_id, $activation_id, $action, $status, $message, $ip, $user_agent, $request_data);
        $stmt->execute();
    }
    
    private function sendSuccess($data) {
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'data' => $data,
            'timestamp' => time(),
            'api_version' => $this->api_version
        ]);
        exit;
    }
    
    private function sendError($message, $code = 400) {
        http_response_code($code);
        echo json_encode([
            'success' => false,
            'error' => $message,
            'code' => $code,
            'timestamp' => time(),
            'api_version' => $this->api_version
        ]);
        exit;
    }
}

// Rate limiting básico
$ip = $_SERVER['REMOTE_ADDR'];
$rate_limit_file = sys_get_temp_dir() . '/license_api_' . md5($ip);

if (file_exists($rate_limit_file)) {
    $requests = json_decode(file_get_contents($rate_limit_file), true);
    $current_time = time();
    
    // Limpiar requests antiguos (más de 1 hora)
    $requests = array_filter($requests, function($timestamp) use ($current_time) {
        return ($current_time - $timestamp) < 3600;
    });
    
    // Verificar límite (máximo 100 requests por hora)
    if (count($requests) >= 100) {
        http_response_code(429);
        echo json_encode([
            'success' => false,
            'error' => 'Rate limit exceeded',
            'code' => 429
        ]);
        exit;
    }
    
    $requests[] = $current_time;
} else {
    $requests = [time()];
}

file_put_contents($rate_limit_file, json_encode($requests));

// Manejar la petición
try {
    $api = new LicenseAPI($license_db_config);
    $api->handleRequest();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error',
        'code' => 500
    ]);
    error_log("License API Error: " . $e->getMessage());
}