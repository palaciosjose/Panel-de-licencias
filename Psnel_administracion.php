<?php
/**
 * Panel de Administración del Servidor de Licencias
 * Version: 1.1 - Con teléfono y sistema de períodos
 */

session_start();

// Configuración de la base de datos del servidor de licencias
$license_db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj', 
    'database' => 'serverbussn_sdcode'
];

// Clase para manejar el sistema de licencias
class LicenseManager {
    private $conn;
    
    public function __construct($db_config) {
        $this->conn = new mysqli(
            $db_config['host'],
            $db_config['username'], 
            $db_config['password'],
            $db_config['database']
        );
        
        if ($this->conn->connect_error) {
            die("Error de conexión: " . $this->conn->connect_error);
        }
        
        $this->conn->set_charset("utf8mb4");
    }
    
    public function authenticate($username, $password) {
        $stmt = $this->conn->prepare("SELECT id, username, password, role FROM license_admins WHERE username = ? AND status = 1");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password'])) {
                $_SESSION['license_admin'] = [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role']
                ];
                
                // Actualizar último login
                $update_stmt = $this->conn->prepare("UPDATE license_admins SET last_login = NOW() WHERE id = ?");
                $update_stmt->bind_param("i", $user['id']);
                $update_stmt->execute();
                
                return true;
            }
        }
        return false;
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['license_admin']);
    }
    
    public function generateLicenseKey() {
        // Generar clave única de 32 caracteres
        $prefix = 'LC'; // License Code
        $timestamp = base_convert(time(), 10, 36);
        $random = bin2hex(random_bytes(12));
        $key = strtoupper($prefix . $timestamp . $random);
        
        // Formatear como XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
        return rtrim(chunk_split($key, 4, '-'), '-');
    }
    
    public function createLicense($data) {
        $license_key = $this->generateLicenseKey();
        
        // Calcular fecha de vencimiento automáticamente
        $start_date = !empty($data['start_date']) ? $data['start_date'] : date('Y-m-d H:i:s');
        $duration_days = !empty($data['duration_days']) ? (int)$data['duration_days'] : null;
        $expires_at = null;
        
        if ($duration_days && $duration_days > 0) {
            $start_timestamp = strtotime($start_date);
            $expires_at = date('Y-m-d H:i:s', $start_timestamp + ($duration_days * 24 * 3600));
        }
        
        $stmt = $this->conn->prepare("
            INSERT INTO licenses (license_key, client_name, client_email, client_phone, product_name, version, 
                                license_type, max_domains, start_date, duration_days, expires_at, notes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->bind_param("sssssssissss", 
            $license_key,
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
            $data['notes']
        );
        
        if ($stmt->execute()) {
            return [
                'success' => true,
                'license_id' => $this->conn->insert_id,
                'license_key' => $license_key,
                'start_date' => $start_date,
                'expires_at' => $expires_at
            ];
        }
        
        return ['success' => false, 'error' => $this->conn->error];
    }
    
    public function getLicenses($limit = 50, $offset = 0, $search = '') {
        $where_clause = '';
        $params = [];
        $types = '';
        
        if (!empty($search)) {
            $where_clause = "WHERE l.client_name LIKE ? OR l.client_email LIKE ? OR l.client_phone LIKE ? OR l.license_key LIKE ?";
            $search_param = "%{$search}%";
            $params = [$search_param, $search_param, $search_param, $search_param];
            $types = 'ssss';
        }
        
        $sql = "
            SELECT l.*, 
                   COUNT(la.id) as activations_count,
                   COUNT(CASE WHEN la.status = 'active' THEN 1 END) as active_activations,
                   CASE 
                       WHEN l.expires_at IS NULL THEN 'permanent'
                       WHEN l.expires_at > NOW() THEN 'active'
                       ELSE 'expired'
                   END as calculated_status,
                   CASE 
                       WHEN l.expires_at IS NOT NULL AND l.expires_at > NOW() 
                       THEN DATEDIFF(l.expires_at, NOW()) 
                       ELSE 0 
                   END as days_remaining
            FROM licenses l
            LEFT JOIN license_activations la ON l.id = la.license_id
            {$where_clause}
            GROUP BY l.id
            ORDER BY l.created_at DESC
            LIMIT ? OFFSET ?
        ";
        
        $params[] = $limit;
        $params[] = $offset;
        $types .= 'ii';
        
        $stmt = $this->conn->prepare($sql);
        if (!empty($params)) {
            $stmt->bind_param($types, ...$params);
        }
        
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
    
    public function getLicenseStats() {
        $result = $this->conn->query("SELECT * FROM license_stats");
        return $result->fetch_assoc();
    }
    
    public function getActivations($license_id = null) {
        $where_clause = $license_id ? "WHERE la.license_id = ?" : "";
        
        $sql = "
            SELECT la.*, l.client_name, l.client_phone, l.license_key
            FROM license_activations la
            JOIN licenses l ON la.license_id = l.id
            {$where_clause}
            ORDER BY la.activated_at DESC
            LIMIT 100
        ";
        
        $stmt = $this->conn->prepare($sql);
        if ($license_id) {
            $stmt->bind_param("i", $license_id);
        }
        
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
    
    public function updateLicenseStatus($license_id, $status) {
        $stmt = $this->conn->prepare("UPDATE licenses SET status = ? WHERE id = ?");
        $stmt->bind_param("si", $status, $license_id);
        return $stmt->execute();
    }
    
    public function getLicenseById($license_id) {
        $stmt = $this->conn->prepare("SELECT * FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function updateLicense($license_id, $data) {
        // Calcular fecha de vencimiento automáticamente
        $start_date = !empty($data['start_date']) ? $data['start_date'] : date('Y-m-d H:i:s');
        $duration_days = !empty($data['duration_days']) ? (int)$data['duration_days'] : null;
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
                'expires_at' => $expires_at
            ];
        }
        
        return ['success' => false, 'error' => $this->conn->error];
    }
    
    public function updateLicensePeriod($license_id, $start_date, $duration_days) {
        $expires_at = null;
        if ($duration_days && $duration_days > 0) {
            $start_timestamp = strtotime($start_date);
            $expires_at = date('Y-m-d H:i:s', $start_timestamp + ($duration_days * 24 * 3600));
        }
        
        $stmt = $this->conn->prepare("UPDATE licenses SET start_date = ?, duration_days = ?, expires_at = ? WHERE id = ?");
        $stmt->bind_param("sisi", $start_date, $duration_days, $expires_at, $license_id);
        return $stmt->execute();
    }
    
    public function deleteLicense($license_id) {
        $stmt = $this->conn->prepare("DELETE FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        return $stmt->execute();
    }
    
    public function getRecentLogs($limit = 50) {
        $sql = "
            SELECT ll.*, l.client_name, l.client_phone, l.license_key 
            FROM license_logs ll
            LEFT JOIN licenses l ON ll.license_id = l.id
            ORDER BY ll.created_at DESC
            LIMIT ?
        ";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
    
    public function getExpiringLicenses($days = 30) {
        $sql = "
            SELECT *, DATEDIFF(expires_at, NOW()) as days_remaining
            FROM licenses 
            WHERE expires_at IS NOT NULL 
            AND expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL ? DAY)
            AND status = 'active'
            ORDER BY expires_at ASC
        ";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("i", $days);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
}

// Inicializar el gestor de licencias
$licenseManager = new LicenseManager($license_db_config);

// Manejar logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Manejar login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($licenseManager->authenticate($username, $password)) {
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = "Credenciales inválidas";
    }
}

// Verificar autenticación
if (!$licenseManager->isLoggedIn()) {
    // Mostrar formulario de login
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Servidor de Licencias - Login</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .login-card { background: rgba(255, 255, 255, 0.95); border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        </style>
    </head>
    <body class="d-flex align-items-center justify-content-center">
        <div class="login-card p-4" style="width: 100%; max-width: 400px;">
            <div class="text-center mb-4">
                <i class="fas fa-key fa-3x text-primary mb-3"></i>
                <h2>Servidor de Licencias</h2>
                <p class="text-muted">Acceso al Panel de Administración v1.1</p>
            </div>
            
            <?php if (isset($login_error)): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <?= htmlspecialchars($login_error) ?>
                </div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="mb-3">
                    <label for="username" class="form-label">Usuario</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-user"></i></span>
                        <input type="text" class="form-control" name="username" required>
                    </div>
                </div>
                
                <div class="mb-3">
                    <label for="password" class="form-label">Contraseña</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                </div>
                
                <button type="submit" name="login" class="btn btn-primary w-100">
                    <i class="fas fa-sign-in-alt me-2"></i>Iniciar Sesión
                </button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Manejar acciones del panel
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['create_license'])) {
        $result = $licenseManager->createLicense($_POST);
        if ($result['success']) {
            $success_message = "Licencia creada exitosamente. Clave: " . $result['license_key'];
            if ($result['expires_at']) {
                $success_message .= "<br>Válida desde: " . date('d/m/Y', strtotime($result['start_date']));
                $success_message .= "<br>Expira: " . date('d/m/Y', strtotime($result['expires_at']));
            }
        } else {
            $error_message = "Error al crear licencia: " . $result['error'];
        }
    }
    
    if (isset($_POST['update_license'])) {
        $license_id = (int)$_POST['edit_license_id'];
        $result = $licenseManager->updateLicense($license_id, $_POST);
        if ($result['success']) {
            $success_message = "Licencia actualizada exitosamente";
            if ($result['expires_at']) {
                $success_message .= "<br>Nueva fecha de expiración: " . date('d/m/Y H:i', strtotime($result['expires_at']));
            }
        } else {
            $error_message = "Error al actualizar licencia: " . $result['error'];
        }
    }
    
    if (isset($_POST['update_status'])) {
        $license_id = (int)$_POST['license_id'];
        $status = $_POST['status'];
        if ($licenseManager->updateLicenseStatus($license_id, $status)) {
            $success_message = "Estado de licencia actualizado";
        } else {
            $error_message = "Error al actualizar estado";
        }
    }
    
    if (isset($_POST['update_period'])) {
        $license_id = (int)$_POST['license_id'];
        $start_date = $_POST['start_date'];
        $duration_days = (int)$_POST['duration_days'];
        if ($licenseManager->updateLicensePeriod($license_id, $start_date, $duration_days)) {
            $success_message = "Período de licencia actualizado";
        } else {
            $error_message = "Error al actualizar período";
        }
    }
    
    if (isset($_POST['delete_license'])) {
        $license_id = (int)$_POST['license_id'];
        if ($licenseManager->deleteLicense($license_id)) {
            $success_message = "Licencia eliminada";
        } else {
            $error_message = "Error al eliminar licencia";
        }
    }
}

// Obtener datos para el dashboard
$stats = $licenseManager->getLicenseStats();
$recent_licenses = $licenseManager->getLicenses(10);
$recent_logs = $licenseManager->getRecentLogs(20);
$recent_activations = $licenseManager->getActivations();
$expiring_licenses = $licenseManager->getExpiringLicenses(30);

$current_tab = $_GET['tab'] ?? 'dashboard';
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Servidor de Licencias - Panel de Administración v1.1</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .sidebar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .nav-link { color: rgba(255,255,255,0.8) !important; }
        .nav-link:hover, .nav-link.active { color: white !important; background: rgba(255,255,255,0.1); }
        .stat-card { border-left: 4px solid #667eea; }
        .table-actions { white-space: nowrap; }
        .license-status-active { background-color: #d4edda; }
        .license-status-expired { background-color: #f8d7da; }
        .license-status-expiring { background-color: #fff3cd; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 px-0">
                <div class="sidebar p-3">
                    <div class="text-center mb-4">
                        <i class="fas fa-key fa-2x text-white mb-2"></i>
                        <h5 class="text-white">Servidor de Licencias</h5>
                        <small class="text-light">v1.1</small>
                    </div>
                    
                    <ul class="nav nav-pills flex-column">
                        <li class="nav-item">
                            <a class="nav-link <?= $current_tab === 'dashboard' ? 'active' : '' ?>" href="?tab=dashboard">
                                <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= $current_tab === 'licenses' ? 'active' : '' ?>" href="?tab=licenses">
                                <i class="fas fa-certificate me-2"></i>Licencias
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= $current_tab === 'expiring' ? 'active' : '' ?>" href="?tab=expiring">
                                <i class="fas fa-exclamation-triangle me-2"></i>Por Expirar
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= $current_tab === 'activations' ? 'active' : '' ?>" href="?tab=activations">
                                <i class="fas fa-plug me-2"></i>Activaciones
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= $current_tab === 'logs' ? 'active' : '' ?>" href="?tab=logs">
                                <i class="fas fa-list-alt me-2"></i>Logs
                            </a>
                        </li>
                        <hr class="text-light">
                        <li class="nav-item">
                            <a class="nav-link" href="?logout=1">
                                <i class="fas fa-sign-out-alt me-2"></i>Cerrar Sesión
                            </a>
                        </li>
                    </ul>
                    
                    <div class="mt-4 text-center">
                        <small class="text-light">
                            Usuario: <?= htmlspecialchars($_SESSION['license_admin']['username']) ?>
                        </small>
                    </div>
                </div>
            </div>
            
            <!-- Contenido principal -->
            <div class="col-md-9 col-lg-10">
                <div class="p-4">
                    <?php if (isset($success_message)): ?>
                        <div class="alert alert-success alert-dismissible fade show">
                            <i class="fas fa-check-circle me-2"></i>
                            <?= $success_message ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (isset($error_message)): ?>
                        <div class="alert alert-danger alert-dismissible fade show">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <?= htmlspecialchars($error_message) ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($current_tab === 'dashboard'): ?>
                        <!-- Dashboard -->
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
                        </div>
                        
                        <!-- Estadísticas -->
                        <div class="row mb-4">
                            <div class="col-md-3 mb-3">
                                <div class="card stat-card">
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <div>
                                                <p class="card-title text-muted mb-1">Total Licencias</p>
                                                <h3 class="mb-0"><?= $stats['total_licenses'] ?? 0 ?></h3>
                                            </div>
                                            <div class="text-primary">
                                                <i class="fas fa-certificate fa-2x"></i>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-3 mb-3">
                                <div class="card stat-card">
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <div>
                                                <p class="card-title text-muted mb-1">Licencias Activas</p>
                                                <h3 class="mb-0 text-success"><?= $stats['active_licenses'] ?? 0 ?></h3>
                                            </div>
                                            <div class="text-success">
                                                <i class="fas fa-check-circle fa-2x"></i>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-3 mb-3">
                                <div class="card stat-card">
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <div>
                                                <p class="card-title text-muted mb-1">Por Expirar (30d)</p>
                                                <h3 class="mb-0 text-warning"><?= $stats['expiring_soon'] ?? 0 ?></h3>
                                            </div>
                                            <div class="text-warning">
                                                <i class="fas fa-exclamation-triangle fa-2x"></i>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-3 mb-3">
                                <div class="card stat-card">
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <div>
                                                <p class="card-title text-muted mb-1">Activaciones</p>
                                                <h3 class="mb-0"><?= $stats['total_activations'] ?? 0 ?></h3>
                                            </div>
                                            <div class="text-info">
                                                <i class="fas fa-plug fa-2x"></i>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <!-- Licencias recientes -->
                            <div class="col-lg-8 mb-4">
                                <div class="card">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-certificate me-2"></i>Licencias Recientes</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-hover">
                                                <thead>
                                                    <tr>
                                                        <th>Cliente</th>
                                                        <th>Teléfono</th>
                                                        <th>Clave</th>
                                                        <th>Estado</th>
                                                        <th>Expira</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <?php foreach ($recent_licenses as $license): ?>
                                                        <tr class="<?= $license['calculated_status'] === 'expired' ? 'license-status-expired' : ($license['days_remaining'] <= 7 && $license['days_remaining'] > 0 ? 'license-status-expiring' : '') ?>">
                                                            <td>
                                                                <strong><?= htmlspecialchars($license['client_name']) ?></strong><br>
                                                                <small class="text-muted"><?= htmlspecialchars($license['client_email']) ?></small>
                                                            </td>
                                                            <td>
                                                                <?php if ($license['client_phone']): ?>
                                                                    <i class="fas fa-phone me-1"></i>
                                                                    <?= htmlspecialchars($license['client_phone']) ?>
                                                                <?php else: ?>
                                                                    <small class="text-muted">N/A</small>
                                                                <?php endif; ?>
                                                            </td>
                                                            <td><code><?= htmlspecialchars(substr($license['license_key'], 0, 20)) ?>...</code></td>
                                                            <td>
                                                                <?php
                                                                $status_colors = [
                                                                    'active' => 'success',
                                                                    'suspended' => 'warning', 
                                                                    'expired' => 'danger',
                                                                    'revoked' => 'dark'
                                                                ];
                                                                $color = $status_colors[$license['status']] ?? 'secondary';
                                                                ?>
                                                                <span class="badge bg-<?= $color ?>"><?= ucfirst($license['status']) ?></span>
                                                            </td>
                                                            <td>
                                                                <?php if ($license['expires_at']): ?>
                                                                    <?= date('d/m/Y', strtotime($license['expires_at'])) ?>
                                                                    <?php if ($license['days_remaining'] > 0): ?>
                                                                        <br><small class="text-muted">(<?= $license['days_remaining'] ?> días)</small>
                                                                    <?php endif; ?>
                                                                <?php else: ?>
                                                                    <span class="badge bg-info">Permanente</span>
                                                                <?php endif; ?>
                                                            </td>
                                                        </tr>
                                                    <?php endforeach; ?>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Logs recientes -->
                            <div class="col-lg-4 mb-4">
                                <div class="card">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-list-alt me-2"></i>Actividad Reciente</h5>
                                    </div>
                                    <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                                        <?php foreach (array_slice($recent_logs, 0, 10) as $log): ?>
                                            <div class="border-bottom py-2">
                                                <div class="d-flex justify-content-between align-items-start">
                                                    <div>
                                                        <small class="text-muted"><?= date('H:i', strtotime($log['created_at'])) ?></small>
                                                        <p class="mb-1 small">
                                                            <?php if ($log['client_name']): ?>
                                                                <strong><?= htmlspecialchars($log['client_name']) ?></strong>
                                                                <?php if ($log['client_phone']): ?>
                                                                    <br><small class="text-muted"><?= htmlspecialchars($log['client_phone']) ?></small>
                                                                <?php endif; ?>
                                                                <br>
                                                            <?php endif; ?>
                                                            <?= htmlspecialchars($log['action']) ?>: <?= htmlspecialchars($log['message']) ?>
                                                        </p>
                                                    </div>
                                                    <span class="badge bg-<?= $log['status'] === 'success' ? 'success' : 'danger' ?> ms-2">
                                                        <?= $log['status'] ?>
                                                    </span>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($current_tab === 'licenses'): ?>
                        <!-- Gestión de Licencias -->
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2><i class="fas fa-certificate me-2"></i>Gestión de Licencias</h2>
                            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createLicenseModal">
                                <i class="fas fa-plus me-2"></i>Nueva Licencia
                            </button>
                        </div>
                        
                        <div class="card">
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Cliente</th>
                                                <th>Contacto</th>
                                                <th>Clave de Licencia</th>
                                                <th>Tipo</th>
                                                <th>Período</th>
                                                <th>Estado</th>
                                                <th>Activaciones</th>
                                                <th>Acciones</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                            $all_licenses = $licenseManager->getLicenses(100);
                                            foreach ($all_licenses as $license): 
                                            ?>
                                                <tr class="<?= $license['calculated_status'] === 'expired' ? 'license-status-expired' : ($license['days_remaining'] <= 7 && $license['days_remaining'] > 0 ? 'license-status-expiring' : '') ?>">
                                                    <td>
                                                        <strong><?= htmlspecialchars($license['client_name']) ?></strong><br>
                                                        <small class="text-muted"><?= htmlspecialchars($license['client_email']) ?></small>
                                                    </td>
                                                    <td>
                                                        <?php if ($license['client_phone']): ?>
                                                            <i class="fas fa-phone me-1"></i>
                                                            <?= htmlspecialchars($license['client_phone']) ?>
                                                        <?php else: ?>
                                                            <small class="text-muted">N/A</small>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td><code><?= htmlspecialchars($license['license_key']) ?></code></td>
                                                    <td><?= ucfirst($license['license_type']) ?></td>
                                                    <td>
                                                        <?php if ($license['start_date']): ?>
                                                            <small>
                                                                <strong>Inicio:</strong> <?= date('d/m/Y', strtotime($license['start_date'])) ?><br>
                                                                <?php if ($license['duration_days']): ?>
                                                                    <strong>Duración:</strong> <?= $license['duration_days'] ?> días<br>
                                                                    <strong>Expira:</strong> <?= date('d/m/Y', strtotime($license['expires_at'])) ?>
                                                                    <?php if ($license['days_remaining'] > 0): ?>
                                                                        <br><span class="text-warning">(<?= $license['days_remaining'] ?> días restantes)</span>
                                                                    <?php endif; ?>
                                                                <?php else: ?>
                                                                    <span class="badge bg-info">Permanente</span>
                                                                <?php endif; ?>
                                                            </small>
                                                        <?php else: ?>
                                                            <span class="badge bg-info">Permanente</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php
                                                        $status_colors = [
                                                            'active' => 'success',
                                                            'suspended' => 'warning', 
                                                            'expired' => 'danger',
                                                            'revoked' => 'dark'
                                                        ];
                                                        $color = $status_colors[$license['status']] ?? 'secondary';
                                                        ?>
                                                        <span class="badge bg-<?= $color ?>"><?= ucfirst($license['status']) ?></span>
                                                        <?php if ($license['calculated_status'] === 'expired'): ?>
                                                            <br><small class="text-danger">Expirada</small>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-info"><?= $license['active_activations'] ?></span>
                                                        /
                                                        <span class="text-muted"><?= $license['max_domains'] ?></span>
                                                    </td>
                                                    <td class="table-actions">
                                                        <div class="btn-group" role="group">
                                                            <button class="btn btn-sm btn-outline-primary" onclick="editLicense(<?= $license['id'] ?>)">
                                                                <i class="fas fa-edit"></i>
                                                            </button>
                                                            <button class="btn btn-sm btn-outline-warning" onclick="editPeriod(<?= $license['id'] ?>, '<?= $license['start_date'] ?>', <?= $license['duration_days'] ?: 0 ?>)">
                                                                <i class="fas fa-calendar-alt"></i>
                                                            </button>
                                                            <button class="btn btn-sm btn-outline-info" onclick="viewActivations(<?= $license['id'] ?>)">
                                                                <i class="fas fa-eye"></i>
                                                            </button>
                                                            <button class="btn btn-sm btn-outline-danger" onclick="deleteLicense(<?= $license['id'] ?>, '<?= htmlspecialchars($license['client_name']) ?>')">
                                                                <i class="fas fa-trash"></i>
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($current_tab === 'expiring'): ?>
                        <!-- Licencias por expirar -->
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2><i class="fas fa-exclamation-triangle me-2"></i>Licencias por Expirar</h2>
                        </div>
                        
                        <div class="card">
                            <div class="card-body">
                                <?php if (!empty($expiring_licenses)): ?>
                                    <div class="table-responsive">
                                        <table class="table table-hover">
                                            <thead>
                                                <tr>
                                                    <th>Cliente</th>
                                                    <th>Contacto</th>
                                                    <th>Clave de Licencia</th>
                                                    <th>Expira</th>
                                                    <th>Días Restantes</th>
                                                    <th>Acciones</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($expiring_licenses as $license): ?>
                                                    <tr class="<?= $license['days_remaining'] <= 7 ? 'license-status-expiring' : '' ?>">
                                                        <td>
                                                            <strong><?= htmlspecialchars($license['client_name']) ?></strong><br>
                                                            <small class="text-muted"><?= htmlspecialchars($license['client_email']) ?></small>
                                                        </td>
                                                        <td>
                                                            <?php if ($license['client_phone']): ?>
                                                                <i class="fas fa-phone me-1"></i>
                                                                <a href="tel:<?= htmlspecialchars($license['client_phone']) ?>"><?= htmlspecialchars($license['client_phone']) ?></a>
                                                            <?php else: ?>
                                                                <small class="text-muted">N/A</small>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td><code><?= htmlspecialchars($license['license_key']) ?></code></td>
                                                        <td><?= date('d/m/Y H:i', strtotime($license['expires_at'])) ?></td>
                                                        <td>
                                                            <?php
                                                            $days = $license['days_remaining'];
                                                            $class = $days <= 3 ? 'danger' : ($days <= 7 ? 'warning' : 'info');
                                                            ?>
                                                            <span class="badge bg-<?= $class ?>"><?= $days ?> días</span>
                                                        </td>
                                                        <td>
                                                            <div class="btn-group" role="group">
                                                                <button class="btn btn-sm btn-outline-success" onclick="extendLicense(<?= $license['id'] ?>)">
                                                                    <i class="fas fa-calendar-plus"></i> Extender
                                                                </button>
                                                                <button class="btn btn-sm btn-outline-primary" onclick="contactClient('<?= htmlspecialchars($license['client_phone']) ?>', '<?= htmlspecialchars($license['client_name']) ?>')">
                                                                    <i class="fas fa-phone"></i> Contactar
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php else: ?>
                                    <div class="text-center py-4">
                                        <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
                                        <h5>¡Excelente!</h5>
                                        <p class="text-muted">No hay licencias próximas a expirar en los próximos 30 días.</p>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($current_tab === 'activations'): ?>
                        <!-- Gestión de Activaciones -->
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2><i class="fas fa-plug me-2"></i>Activaciones de Licencias</h2>
                            <?php if (isset($_GET['license'])): ?>
                                <a href="?tab=activations" class="btn btn-secondary">
                                    <i class="fas fa-list me-2"></i>Ver Todas
                                </a>
                            <?php endif; ?>
                        </div>
                        
                        <?php
                        $license_filter = isset($_GET['license']) ? (int)$_GET['license'] : null;
                        $activations = $licenseManager->getActivations($license_filter);
                        ?>
                        
                        <div class="card">
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Cliente</th>
                                                <th>Contacto</th>
                                                <th>Clave de Licencia</th>
                                                <th>Dominio</th>
                                                <th>IP</th>
                                                <th>Estado</th>
                                                <th>Activada</th>
                                                <th>Última Verificación</th>
                                                <th>Verificaciones</th>
                                                <th>Acciones</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (!empty($activations)): ?>
                                                <?php foreach ($activations as $activation): ?>
                                                    <tr>
                                                        <td>
                                                            <strong><?= htmlspecialchars($activation['client_name']) ?></strong>
                                                        </td>
                                                        <td>
                                                            <?php if ($activation['client_phone']): ?>
                                                                <i class="fas fa-phone me-1"></i>
                                                                <?= htmlspecialchars($activation['client_phone']) ?>
                                                            <?php else: ?>
                                                                <small class="text-muted">N/A</small>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td>
                                                            <code><?= htmlspecialchars(substr($activation['license_key'], 0, 20)) ?>...</code>
                                                        </td>
                                                        <td>
                                                            <i class="fas fa-globe me-2"></i>
                                                            <?= htmlspecialchars($activation['domain']) ?>
                                                        </td>
                                                        <td>
                                                            <small class="text-muted"><?= htmlspecialchars($activation['ip_address']) ?></small>
                                                        </td>
                                                        <td>
                                                            <?php
                                                            $status_colors = [
                                                                'active' => 'success',
                                                                'inactive' => 'warning',
                                                                'blocked' => 'danger'
                                                            ];
                                                            $color = $status_colors[$activation['status']] ?? 'secondary';
                                                            ?>
                                                            <span class="badge bg-<?= $color ?>"><?= ucfirst($activation['status']) ?></span>
                                                        </td>
                                                        <td>
                                                            <small><?= date('d/m/Y H:i', strtotime($activation['activated_at'])) ?></small>
                                                        </td>
                                                        <td>
                                                            <small><?= date('d/m/Y H:i', strtotime($activation['last_check'])) ?></small>
                                                        </td>
                                                        <td>
                                                            <span class="badge bg-info"><?= $activation['check_count'] ?></span>
                                                        </td>
                                                        <td>
                                                            <div class="btn-group" role="group">
                                                                <button class="btn btn-sm btn-outline-info" onclick="viewActivationDetails(<?= $activation['id'] ?>)">
                                                                    <i class="fas fa-eye"></i>
                                                                </button>
                                                                <?php if ($activation['status'] === 'active'): ?>
                                                                    <button class="btn btn-sm btn-outline-warning" onclick="blockActivation(<?= $activation['id'] ?>)">
                                                                        <i class="fas fa-ban"></i>
                                                                    </button>
                                                                <?php endif; ?>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="10" class="text-center py-4">
                                                        <i class="fas fa-plug fa-2x text-muted mb-2"></i>
                                                        <p class="text-muted mb-0">No hay activaciones registradas</p>
                                                    </td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($current_tab === 'logs'): ?>
                        <!-- Logs del Sistema -->
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2><i class="fas fa-list-alt me-2"></i>Logs del Sistema</h2>
                            <div class="btn-group" role="group">
                                <button class="btn btn-outline-secondary" onclick="refreshLogs()">
                                    <i class="fas fa-sync me-2"></i>Actualizar
                                </button>
                                <button class="btn btn-outline-danger" onclick="clearOldLogs()">
                                    <i class="fas fa-trash me-2"></i>Limpiar Antiguos
                                </button>
                            </div>
                        </div>
                        
                        <!-- Filtros -->
                        <div class="card mb-4">
                            <div class="card-body">
                                <form method="GET" class="row g-3">
                                    <input type="hidden" name="tab" value="logs">
                                    <div class="col-md-3">
                                        <select class="form-select" name="action_filter">
                                            <option value="">Todas las acciones</option>
                                            <option value="activation" <?= ($_GET['action_filter'] ?? '') === 'activation' ? 'selected' : '' ?>>Activaciones</option>
                                            <option value="verification" <?= ($_GET['action_filter'] ?? '') === 'verification' ? 'selected' : '' ?>>Verificaciones</option>
                                            <option value="deactivation" <?= ($_GET['action_filter'] ?? '') === 'deactivation' ? 'selected' : '' ?>>Desactivaciones</option>
                                            <option value="error" <?= ($_GET['action_filter'] ?? '') === 'error' ? 'selected' : '' ?>>Errores</option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <select class="form-select" name="status_filter">
                                            <option value="">Todos los estados</option>
                                            <option value="success" <?= ($_GET['status_filter'] ?? '') === 'success' ? 'selected' : '' ?>>Éxito</option>
                                            <option value="failure" <?= ($_GET['status_filter'] ?? '') === 'failure' ? 'selected' : '' ?>>Fallo</option>
                                            <option value="warning" <?= ($_GET['status_filter'] ?? '') === 'warning' ? 'selected' : '' ?>>Advertencia</option>
                                        </select>
                                    </div>
                                    <div class="col-md-4">
                                        <input type="text" class="form-control" name="search" placeholder="Buscar en logs..." value="<?= htmlspecialchars($_GET['search'] ?? '') ?>">
                                    </div>
                                    <div class="col-md-2">
                                        <button type="submit" class="btn btn-primary w-100">
                                            <i class="fas fa-search"></i> Filtrar
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover table-sm">
                                        <thead>
                                            <tr>
                                                <th>Fecha/Hora</th>
                                                <th>Cliente</th>
                                                <th>Contacto</th>
                                                <th>Acción</th>
                                                <th>Estado</th>
                                                <th>Mensaje</th>
                                                <th>IP</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($recent_logs as $log): ?>
                                                <tr>
                                                    <td>
                                                        <small><?= date('d/m/Y H:i:s', strtotime($log['created_at'])) ?></small>
                                                    </td>
                                                    <td>
                                                        <?php if ($log['client_name']): ?>
                                                            <small><?= htmlspecialchars($log['client_name']) ?></small>
                                                        <?php else: ?>
                                                            <small class="text-muted">-</small>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php if ($log['client_phone']): ?>
                                                            <small><?= htmlspecialchars($log['client_phone']) ?></small>
                                                        <?php else: ?>
                                                            <small class="text-muted">-</small>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php
                                                        $action_icons = [
                                                            'activation' => 'fas fa-plug text-success',
                                                            'verification' => 'fas fa-check-circle text-info',
                                                            'deactivation' => 'fas fa-unlink text-warning',
                                                            'error' => 'fas fa-exclamation-triangle text-danger'
                                                        ];
                                                        $icon = $action_icons[$log['action']] ?? 'fas fa-info';
                                                        ?>
                                                        <i class="<?= $icon ?> me-1"></i>
                                                        <small><?= ucfirst($log['action']) ?></small>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-<?= $log['status'] === 'success' ? 'success' : ($log['status'] === 'warning' ? 'warning' : 'danger') ?> badge-sm">
                                                            <?= ucfirst($log['status']) ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <small><?= htmlspecialchars(substr($log['message'], 0, 60)) ?><?= strlen($log['message']) > 60 ? '...' : '' ?></small>
                                                    </td>
                                                    <td>
                                                        <small class="text-muted"><?= htmlspecialchars($log['ip_address']) ?></small>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal para crear licencia -->
    <div class="modal fade" id="createLicenseModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-plus me-2"></i>Crear Nueva Licencia
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <div class="row">
                            <!-- Información del Cliente -->
                            <div class="col-md-6">
                                <h6 class="mb-3 text-primary">
                                    <i class="fas fa-user me-2"></i>Información del Cliente
                                </h6>
                                
                                <div class="mb-3">
                                    <label for="client_name" class="form-label">Nombre del Cliente</label>
                                    <input type="text" class="form-control" name="client_name" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="client_email" class="form-label">Email del Cliente</label>
                                    <input type="email" class="form-control" name="client_email" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="client_phone" class="form-label">Teléfono del Cliente</label>
                                    <input type="tel" class="form-control" name="client_phone" placeholder="+57 300 123 4567">
                                    <div class="form-text">Incluye código de país para mejor contacto</div>
                                </div>
                            </div>
                            
                            <!-- Configuración de Licencia -->
                            <div class="col-md-6">
                                <h6 class="mb-3 text-info">
                                    <i class="fas fa-cog me-2"></i>Configuración de Licencia
                                </h6>
                                
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="product_name" class="form-label">Producto</label>
                                            <input type="text" class="form-control" name="product_name" value="Sistema de Códigos">
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="version" class="form-label">Versión</label>
                                            <input type="text" class="form-control" name="version" value="1.0">
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="license_type" class="form-label">Tipo de Licencia</label>
                                            <select class="form-select" name="license_type">
                                                <option value="single">Single Domain</option>
                                                <option value="multiple">Multiple Domains</option>
                                                <option value="unlimited">Unlimited Domains</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="max_domains" class="form-label">Máximo Dominios</label>
                                            <input type="number" class="form-control" name="max_domains" value="1" min="1">
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Configuración de Período -->
                        <div class="row">
                            <div class="col-12">
                                <h6 class="mb-3 text-warning">
                                    <i class="fas fa-calendar-alt me-2"></i>Configuración de Período
                                </h6>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label for="start_date" class="form-label">Fecha de Inicio</label>
                                    <input type="datetime-local" class="form-control" name="start_date" 
                                           value="<?= date('Y-m-d\TH:i') ?>">
                                    <div class="form-text">Cuándo comienza la validez de la licencia</div>
                                </div>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label for="duration_days" class="form-label">Duración (días)</label>
                                    <select class="form-select" name="duration_days" id="duration_days">
                                        <option value="">Permanente</option>
                                        <option value="7">7 días (Prueba)</option>
                                        <option value="30">30 días (1 mes)</option>
                                        <option value="90">90 días (3 meses)</option>
                                        <option value="180">180 días (6 meses)</option>
                                        <option value="365">365 días (1 año)</option>
                                        <option value="730">730 días (2 años)</option>
                                        <option value="custom">Personalizado...</option>
                                    </select>
                                    <div class="form-text">Vacío = licencia permanente</div>
                                </div>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label for="custom_duration" class="form-label">Días personalizados</label>
                                    <input type="number" class="form-control" name="custom_duration" 
                                           id="custom_duration" min="1" max="3650" style="display: none;">
                                    <div class="form-text" id="expiry_preview"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="notes" class="form-label">Notas</label>
                            <textarea class="form-control" name="notes" rows="3" 
                                      placeholder="Notas adicionales sobre esta licencia..."></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" name="create_license" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Crear Licencia
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Modal para editar licencia completa -->
    <div class="modal fade" id="editLicenseModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-edit me-2"></i>Editar Licencia
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" id="editLicenseForm">
                    <input type="hidden" name="edit_license_id" id="edit_license_id">
                    <div class="modal-body">
                        <div class="row">
                            <!-- Información del Cliente -->
                            <div class="col-md-6">
                                <h6 class="mb-3 text-primary">
                                    <i class="fas fa-user me-2"></i>Información del Cliente
                                </h6>
                                
                                <div class="mb-3">
                                    <label for="edit_client_name" class="form-label">Nombre del Cliente</label>
                                    <input type="text" class="form-control" name="client_name" id="edit_client_name" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="edit_client_email" class="form-label">Email del Cliente</label>
                                    <input type="email" class="form-control" name="client_email" id="edit_client_email" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="edit_client_phone" class="form-label">Teléfono del Cliente</label>
                                    <input type="tel" class="form-control" name="client_phone" id="edit_client_phone">
                                </div>
                            </div>
                            
                            <!-- Configuración de Licencia -->
                            <div class="col-md-6">
                                <h6 class="mb-3 text-info">
                                    <i class="fas fa-cog me-2"></i>Configuración de Licencia
                                </h6>
                                
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="edit_product_name" class="form-label">Producto</label>
                                            <input type="text" class="form-control" name="product_name" id="edit_product_name">
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="edit_version" class="form-label">Versión</label>
                                            <input type="text" class="form-control" name="version" id="edit_version">
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="edit_license_type" class="form-label">Tipo de Licencia</label>
                                            <select class="form-select" name="license_type" id="edit_license_type">
                                                <option value="single">Single Domain</option>
                                                <option value="multiple">Multiple Domains</option>
                                                <option value="unlimited">Unlimited Domains</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label for="edit_max_domains" class="form-label">Máximo Dominios</label>
                                            <input type="number" class="form-control" name="max_domains" id="edit_max_domains" min="1">
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="edit_status" class="form-label">Estado</label>
                                    <select class="form-select" name="status" id="edit_status">
                                        <option value="active">Activa</option>
                                        <option value="suspended">Suspendida</option>
                                        <option value="expired">Expirada</option>
                                        <option value="revoked">Revocada</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Configuración de Período -->
                        <div class="row">
                            <div class="col-12">
                                <h6 class="mb-3 text-warning">
                                    <i class="fas fa-calendar-alt me-2"></i>Configuración de Período
                                </h6>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label for="edit_start_date" class="form-label">Fecha de Inicio</label>
                                    <input type="datetime-local" class="form-control" name="start_date" id="edit_start_date">
                                </div>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label for="edit_duration_days" class="form-label">Duración (días)</label>
                                    <select class="form-select" name="duration_days" id="edit_duration_days">
                                        <option value="">Permanente</option>
                                        <option value="7">7 días (Prueba)</option>
                                        <option value="30">30 días (1 mes)</option>
                                        <option value="90">90 días (3 meses)</option>
                                        <option value="180">180 días (6 meses)</option>
                                        <option value="365">365 días (1 año)</option>
                                        <option value="730">730 días (2 años)</option>
                                        <option value="custom">Personalizado...</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label for="edit_custom_duration" class="form-label">Días personalizados</label>
                                    <input type="number" class="form-control" name="custom_duration" 
                                           id="edit_custom_duration" min="1" max="3650" style="display: none;">
                                    <div class="form-text" id="edit_expiry_preview"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit_notes" class="form-label">Notas</label>
                            <textarea class="form-control" name="notes" id="edit_notes" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" name="update_license" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Actualizar Licencia
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Modal para editar período -->
    <div class="modal fade" id="editPeriodModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-calendar-alt me-2"></i>Editar Período de Licencia
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" id="editPeriodForm">
                    <input type="hidden" name="license_id" id="period_license_id">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="period_start_date" class="form-label">Fecha de Inicio</label>
                            <input type="datetime-local" class="form-control" name="start_date" id="period_start_date" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="period_duration_days" class="form-label">Duración (días)</label>
                            <select class="form-select" name="duration_days" id="period_duration_days">
                                <option value="">Permanente</option>
                                <option value="7">7 días (Prueba)</option>
                                <option value="30">30 días (1 mes)</option>
                                <option value="90">90 días (3 meses)</option>
                                <option value="180">180 días (6 meses)</option>
                                <option value="365">365 días (1 año)</option>
                                <option value="730">730 días (2 años)</option>
                            </select>
                        </div>
                        
                        <div class="alert alert-info">
                            <small>
                                <i class="fas fa-info-circle me-2"></i>
                                La fecha de expiración se calculará automáticamente basada en la fecha de inicio y la duración.
                            </small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" name="update_period" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Actualizar Período
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Manejar duración personalizada
        document.getElementById('duration_days').addEventListener('change', function() {
            const customField = document.getElementById('custom_duration');
            if (this.value === 'custom') {
                customField.style.display = 'block';
                customField.required = true;
            } else {
                customField.style.display = 'none';
                customField.required = false;
                updateExpiryPreview();
            }
        });
        
        function updateExpiryPreview() {
            const startDate = document.querySelector('[name="start_date"]').value;
            const durationSelect = document.getElementById('duration_days');
            const customDuration = document.getElementById('custom_duration');
            const preview = document.getElementById('expiry_preview');
            
            if (!startDate) {
                preview.innerHTML = '';
                return;
            }
            
            let duration = durationSelect.value === 'custom' ? customDuration.value : durationSelect.value;
            
            if (duration && duration > 0) {
                const start = new Date(startDate);
                const expiry = new Date(start.getTime() + (duration * 24 * 60 * 60 * 1000));
                preview.innerHTML = `<i class="fas fa-clock me-1"></i>Expira: ${expiry.toLocaleDateString('es-ES')}`;
                preview.className = 'form-text text-info';
            } else {
                preview.innerHTML = '<i class="fas fa-infinity me-1"></i>Licencia permanente';
                preview.className = 'form-text text-success';
            }
        }
        
        // Event listeners para actualizar preview
        document.addEventListener('DOMContentLoaded', function() {
            const startDateField = document.querySelector('[name="start_date"]');
            const durationField = document.getElementById('duration_days');
            const customField = document.getElementById('custom_duration');
            
            if (startDateField) startDateField.addEventListener('change', updateExpiryPreview);
            if (durationField) durationField.addEventListener('change', updateExpiryPreview);
            if (customField) customField.addEventListener('input', updateExpiryPreview);
            
            updateExpiryPreview();
        });
        
        // Manejar duración personalizada en el modal de edición
        document.getElementById('edit_duration_days').addEventListener('change', function() {
            const customField = document.getElementById('edit_custom_duration');
            if (this.value === 'custom') {
                customField.style.display = 'block';
                customField.required = true;
            } else {
                customField.style.display = 'none';
                customField.required = false;
                updateEditExpiryPreview();
            }
        });
        
        function updateEditExpiryPreview() {
            const startDate = document.getElementById('edit_start_date').value;
            const durationSelect = document.getElementById('edit_duration_days');
            const customDuration = document.getElementById('edit_custom_duration');
            const preview = document.getElementById('edit_expiry_preview');
            
            if (!startDate) {
                preview.innerHTML = '';
                return;
            }
            
            let duration = durationSelect.value === 'custom' ? customDuration.value : durationSelect.value;
            
            if (duration && duration > 0) {
                const start = new Date(startDate);
                const expiry = new Date(start.getTime() + (duration * 24 * 60 * 60 * 1000));
                preview.innerHTML = `<i class="fas fa-clock me-1"></i>Expira: ${expiry.toLocaleDateString('es-ES')}`;
                preview.className = 'form-text text-info';
            } else {
                preview.innerHTML = '<i class="fas fa-infinity me-1"></i>Licencia permanente';
                preview.className = 'form-text text-success';
            }
        }
        
        // Event listeners para actualizar preview en edición
        const editStartDateField = document.getElementById('edit_start_date');
        const editDurationField = document.getElementById('edit_duration_days');
        const editCustomField = document.getElementById('edit_custom_duration');
        
        if (editStartDateField) editStartDateField.addEventListener('change', updateEditExpiryPreview);
        if (editDurationField) editDurationField.addEventListener('change', updateEditExpiryPreview);
        if (editCustomField) editCustomField.addEventListener('input', updateEditExpiryPreview);
        
        function editLicense(id) {
            // Obtener datos de la licencia
            fetch('license_ajax.php?action=get_license&id=' + id)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const license = data.license;
                        
                        // Llenar el formulario
                        document.getElementById('edit_license_id').value = license.id;
                        document.getElementById('edit_client_name').value = license.client_name || '';
                        document.getElementById('edit_client_email').value = license.client_email || '';
                        document.getElementById('edit_client_phone').value = license.client_phone || '';
                        document.getElementById('edit_product_name').value = license.product_name || '';
                        document.getElementById('edit_version').value = license.version || '';
                        document.getElementById('edit_license_type').value = license.license_type || '';
                        document.getElementById('edit_max_domains').value = license.max_domains || '';
                        document.getElementById('edit_status').value = license.status || '';
                        document.getElementById('edit_notes').value = license.notes || '';
                        
                        // Configurar fecha de inicio
                        if (license.start_date && license.start_date !== '0000-00-00 00:00:00') {
                            const startDate = new Date(license.start_date);
                            const isoString = startDate.toISOString().slice(0, 16);
                            document.getElementById('edit_start_date').value = isoString;
                        }
                        
                        // Configurar duración
                        if (license.duration_days) {
                            const durationSelect = document.getElementById('edit_duration_days');
                            const standardValues = ['7', '30', '90', '180', '365', '730'];
                            
                            if (standardValues.includes(license.duration_days.toString())) {
                                durationSelect.value = license.duration_days;
                            } else {
                                durationSelect.value = 'custom';
                                document.getElementById('edit_custom_duration').style.display = 'block';
                                document.getElementById('edit_custom_duration').value = license.duration_days;
                            }
                        } else {
                            document.getElementById('edit_duration_days').value = '';
                        }
                        
                        updateEditExpiryPreview();
                        
                        // Mostrar modal
                        const modal = new bootstrap.Modal(document.getElementById('editLicenseModal'));
                        modal.show();
                    } else {
                        alert('Error al cargar datos de la licencia: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('Error de conexión: ' + error.message);
                });
        }
        
        // Manejar envío del formulario de edición con AJAX
        document.getElementById('editLicenseForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.append('action', 'update_license');
            formData.append('license_id', document.getElementById('edit_license_id').value);
            
            // Mostrar loading
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Actualizando...';
            submitBtn.disabled = true;
            
            fetch('license_ajax.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Cerrar modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('editLicenseModal'));
                    modal.hide();
                    
                    // Mostrar mensaje de éxito y recargar página
                    alert('Licencia actualizada exitosamente');
                    window.location.reload();
                } else {
                    alert('Error al actualizar licencia: ' + data.error);
                }
            })
            .catch(error => {
                alert('Error de conexión: ' + error.message);
            })
            .finally(() => {
                // Restaurar botón
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
        });
        
        // Función mejorada para eliminar licencia
        function deleteLicense(id, clientName) {
            if (confirm('¿Estás seguro de eliminar la licencia de "' + clientName + '"?\n\nEsta acción no se puede deshacer.')) {
                const formData = new FormData();
                formData.append('action', 'delete_license');
                formData.append('license_id', id);
                
                fetch('license_ajax.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Licencia eliminada exitosamente');
                        window.location.reload();
                    } else {
                        alert('Error al eliminar licencia: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('Error de conexión: ' + error.message);
                });
            }
        }
        
        function editPeriod(id, startDate, durationDays) {
            document.getElementById('period_license_id').value = id;
            document.getElementById('period_start_date').value = startDate ? startDate.replace(' ', 'T').substring(0, 16) : '';
            document.getElementById('period_duration_days').value = durationDays || '';
            
            const modal = new bootstrap.Modal(document.getElementById('editPeriodModal'));
            modal.show();
        }
        
        function viewActivations(id) {
            window.location.href = '?tab=activations&license=' + id;
        }
        
        function extendLicense(id) {
            const extension = prompt('¿Cuántos días adicionales desea agregar?', '30');
            if (extension && parseInt(extension) > 0) {
                // Implementar extensión de licencia
                alert('Función de extensión - Agregar ' + extension + ' días a licencia ID: ' + id);
            }
        }
        
        function contactClient(phone, clientName) {
            if (phone) {
                window.open('tel:' + phone);
            } else {
                alert('No hay número de teléfono registrado para ' + clientName);
            }
        }
        
        function viewActivationDetails(activationId) {
            // Mostrar detalles de activación
            alert('Detalles de activación ID: ' + activationId);
        }
        
        function blockActivation(activationId) {
            if (confirm('¿Está seguro de bloquear esta activación?')) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = '<input type="hidden" name="block_activation" value="1"><input type="hidden" name="activation_id" value="' + activationId + '">';
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function refreshLogs() {
            window.location.reload();
        }
        
        function clearOldLogs() {
            if (confirm('¿Está seguro de eliminar logs antiguos (más de 90 días)?')) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = '<input type="hidden" name="clear_old_logs" value="1">';
                document.body.appendChild(form);
                form.submit();
            }
        }
    </script>
</body>
</html>