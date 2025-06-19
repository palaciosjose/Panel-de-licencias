<?php
/**
 * API para el Panel de Administración de Licencias
 * Maneja solicitudes AJAX para obtener y actualizar datos.
 * Version: 1.0
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Considera restringir esto en producción a tu dominio
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejar preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

session_start();

// Configuración de la base de datos (copiada de Psnel_administracion.php)
$license_db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj',
    'database' => 'serverbussn_sdcode'
];

// Incluir la clase LicenseManager desde su archivo separado
require_once 'LicenseManager.class.php';

try {
    $licenseManager = new LicenseManager($license_db_config);
} catch (Exception $e) {
    // Si falla la conexión a la DB, devolver error JSON
    echo json_encode(['success' => false, 'error' => 'Error de conexión a la base de datos.', 'code' => 500]);
    http_response_code(500);
    exit;
}

// Verifica si el usuario está logueado a través de la sesión
if (!isset($_SESSION['license_admin']) || empty($_SESSION['license_admin']['id'])) {
    echo json_encode(['success' => false, 'error' => 'No autorizado. Se requiere iniciar sesión.']);
    http_response_code(401);
    exit;
}


$action = $_GET['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    case 'get_license_details':
        $license_id = (int)($_GET['id'] ?? 0);
        if ($license_id > 0) {
            $license_details = $licenseManager->getLicenseDetails($license_id);
            if ($license_details) {
                echo json_encode(['success' => true, 'license' => $license_details]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Licencia no encontrada']);
                http_response_code(404);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'ID de licencia inválido']);
            http_response_code(400);
        }
        break;

    case 'update_license':
        $input = json_decode(file_get_contents('php://input'), true); // Para manejar JSON POST
        if (!$input) {
            $input = $_POST; // Fallback para POST tradicionales si Content-Type no es application/json
        }

        $required_fields = ['id', 'client_name', 'client_email', 'product_name', 'version', 'license_type', 'max_domains', 'notes', 'status'];
        foreach ($required_fields as $field) {
            if (!isset($input[$field])) {
                echo json_encode(['success' => false, 'error' => "Falta el campo requerido: $field"]);
                http_response_code(400);
                exit;
            }
        }

        $result = $licenseManager->updateLicense($input);
        if ($result['success']) {
            echo json_encode(['success' => true, 'message' => 'Licencia actualizada exitosamente']);
        } else {
            echo json_encode(['success' => false, 'error' => 'Error al actualizar licencia: ' . ($result['error'] ?? 'Desconocido')]);
            http_response_code(500);
        }
        break;

    case 'get_stats':
        $stats = $licenseManager->getLicenseStats();
        echo json_encode(['success' => true, 'stats' => $stats]);
        break;

    case 'get_activation_details':
        $activation_id = (int)($_GET['id'] ?? 0);
        if ($activation_id > 0) {
            $stmt = $licenseManager->getDbConnection()->prepare("SELECT * FROM license_activations WHERE id = ?");
            $stmt->bind_param("i", $activation_id);
            $stmt->execute();
            $activation_details = $stmt->get_result()->fetch_assoc();
            if ($activation_details) {
                echo json_encode(['success' => true, 'activation' => $activation_details]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Activación no encontrada']);
                http_response_code(404);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'ID de activación inválido']);
            http_response_code(400);
        }
        break;

    case 'block_activation':
        $activation_id = (int)($_POST['activation_id'] ?? 0);
        if ($activation_id > 0) {
            $stmt = $licenseManager->getDbConnection()->prepare("UPDATE license_activations SET status = 'blocked' WHERE id = ?");
            $stmt->bind_param("i", $activation_id);
            if ($stmt->execute()) {
                echo json_encode(['success' => true, 'message' => 'Activación bloqueada']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Error al bloquear activación']);
                http_response_code(500);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'ID de activación inválido']);
            http_response_code(400);
        }
        break;

    case 'clear_old_logs':
        $days_old = 90; // Define cuántos días atrás limpiar
        $stmt = $licenseManager->getDbConnection()->prepare("DELETE FROM license_logs WHERE created_at < NOW() - INTERVAL ? DAY");
        $stmt->bind_param("i", $days_old);
        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'Logs antiguos eliminados']);
        } else {
            echo json_encode(['success' => false, 'error' => 'Error al eliminar logs']);
            http_response_code(500);
        }
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Acción inválida']);
        http_response_code(400);
        break;
}
?>