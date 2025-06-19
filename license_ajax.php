<?php
/**
 * Endpoint AJAX para operaciones de licencias
 * Maneja obtención y actualización de datos de licencias
 */

session_start();

// Verificar autenticación
if (!isset($_SESSION['license_admin'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'No autenticado']);
    exit;
}

// Configuración de la base de datos
$license_db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj', 
    'database' => 'serverbussn_sdcode'
];

class LicenseAjaxHandler {
    private $conn;
    
    public function __construct($db_config) {
        $this->conn = new mysqli(
            $db_config['host'],
            $db_config['username'], 
            $db_config['password'],
            $db_config['database']
        );
        
        if ($this->conn->connect_error) {
            throw new Exception("Error de conexión: " . $this->conn->connect_error);
        }
        
        $this->conn->set_charset("utf8mb4");
    }
    
    public function getLicense($license_id) {
        $stmt = $this->conn->prepare("SELECT * FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function updateLicense($license_id, $data) {
        // Calcular fecha de vencimiento automáticamente
        $start_date = !empty($data['start_date']) ? $data['start_date'] : date('Y-m-d H:i:s');
        $duration_days = !empty($data['duration_days']) ? (int)$data['duration_days'] : null;
        
        // Si se seleccionó "custom", usar el valor personalizado
        if ($data['duration_days'] === 'custom' && !empty($data['custom_duration'])) {
            $duration_days = (int)$data['custom_duration'];
        }
        
        $expires_at = null;
        if ($duration_days && $duration_days > 0) {
            $start_timestamp = strtotime($start_date);
            $expires_at = date('Y-m-d H:i:s', $start_timestamp + ($duration_days * 24 * 3600));
        }
        
        $stmt = $this->conn->prepare("
            UPDATE licenses SET 
                client_name = ?, client_email = ?, client_phone = ?, 
                product_name = ?, version = ?, license_type = ?, max_domains = ?, 
                start_date = ?, duration_days = ?, expires_at = ?, 
                status = ?, notes = ?
            WHERE id = ?
        ");
        
        $stmt->bind_param("ssssssisssssi", 
            $data['client_name'],
            $data['client_email'],
            $data['client_phone'],
            $data['product_name'],
            $data['version'],
            $data['license_type'],
            $data['max_domains'],
            $start_date,
            $duration_days,
            $expires_at,
            $data['status'],
            $data['notes'],
            $license_id
        );
        
        if ($stmt->execute()) {
            return [
                'success' => true,
                'start_date' => $start_date,
                'expires_at' => $expires_at,
                'duration_days' => $duration_days
            ];
        }
        
        return ['success' => false, 'error' => $this->conn->error];
    }
    
    public function deleteLicense($license_id) {
        // Primero verificar si tiene activaciones
        $stmt = $this->conn->prepare("SELECT COUNT(*) as count FROM license_activations WHERE license_id = ?");
        $stmt->bind_param("i", $license_id);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if ($result['count'] > 0) {
            return ['success' => false, 'error' => 'No se puede eliminar: la licencia tiene activaciones'];
        }
        
        // Eliminar la licencia
        $stmt = $this->conn->prepare("DELETE FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        
        if ($stmt->execute()) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => $this->conn->error];
    }
    
    public function getActivations($license_id) {
        $stmt = $this->conn->prepare("
            SELECT id, domain, ip_address, status, activated_at, last_check, check_count
            FROM license_activations 
            WHERE license_id = ? 
            ORDER BY activated_at DESC
        ");
        $stmt->bind_param("i", $license_id);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
}

// Manejar requests
header('Content-Type: application/json');

try {
    $handler = new LicenseAjaxHandler($license_db_config);
    $action = $_GET['action'] ?? $_POST['action'] ?? '';
    
    switch ($action) {
        case 'get_license':
            if (!isset($_GET['id'])) {
                throw new Exception('ID de licencia requerido');
            }
            
            $license = $handler->getLicense((int)$_GET['id']);
            if ($license) {
                echo json_encode(['success' => true, 'license' => $license]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Licencia no encontrada']);
            }
            break;
            
        case 'update_license':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('Método no permitido');
            }
            
            if (!isset($_POST['license_id'])) {
                throw new Exception('ID de licencia requerido');
            }
            
            $result = $handler->updateLicense((int)$_POST['license_id'], $_POST);
            echo json_encode($result);
            break;
            
        case 'delete_license':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('Método no permitido');
            }
            
            if (!isset($_POST['license_id'])) {
                throw new Exception('ID de licencia requerido');
            }
            
            $result = $handler->deleteLicense((int)$_POST['license_id']);
            echo json_encode($result);
            break;
            
        case 'get_activations':
            if (!isset($_GET['license_id'])) {
                throw new Exception('ID de licencia requerido');
            }
            
            $activations = $handler->getActivations((int)$_GET['license_id']);
            echo json_encode(['success' => true, 'activations' => $activations]);
            break;
            
        default:
            throw new Exception('Acción no válida');
    }
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>