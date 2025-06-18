<?php
/**
 * Panel de Administración del Servidor de Licencias
 * Version: 1.0
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
        $expires_at = !empty($data['expires_at']) ? $data['expires_at'] : null;
        
        $stmt = $this->conn->prepare("
            INSERT INTO licenses (license_key, client_name, client_email, product_name, version, 
                                license_type, max_domains, expires_at, notes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->bind_param("ssssssiss", 
            $license_key,
            $data['client_name'],
            $data['client_email'], 
            $data['product_name'],
            $data['version'],
            $data['license_type'],
            $data['max_domains'],
            $expires_at,
            $data['notes']
        );
        
        if ($stmt->execute()) {
            return [
                'success' => true,
                'license_id' => $this->conn->insert_id,
                'license_key' => $license_key
            ];
        }
        
        return ['success' => false, 'error' => $this->conn->error];
    }
    
    public function getLicenses($limit = 50, $offset = 0, $search = '') {
        $where_clause = '';
        $params = [];
        $types = '';
        
        if (!empty($search)) {
            $where_clause = "WHERE l.client_name LIKE ? OR l.client_email LIKE ? OR l.license_key LIKE ?";
            $search_param = "%{$search}%";
            $params = [$search_param, $search_param, $search_param];
            $types = 'sss';
        }
        
        $sql = "
            SELECT l.*, 
                   COUNT(la.id) as activations_count,
                   COUNT(CASE WHEN la.status = 'active' THEN 1 END) as active_activations
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
            SELECT la.*, l.client_name, l.license_key
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
    
    public function deleteLicense($license_id) {
        $stmt = $this->conn->prepare("DELETE FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        return $stmt->execute();
    }
    
    public function getRecentLogs($limit = 50) {
        $sql = "
            SELECT ll.*, l.client_name, l.license_key 
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
                <p class="text-muted">Acceso al Panel de Administración</p>
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
        } else {
            $error_message = "Error al crear licencia: " . $result['error'];
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

$current_tab = $_GET['tab'] ?? 'dashboard';
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Servidor de Licencias - Panel de Administración</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .sidebar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .nav-link { color: rgba(255,255,255,0.8) !important; }
        .nav-link:hover, .nav-link.active { color: white !important; background: rgba(255,255,255,0.1); }
        .stat-card { border-left: 4px solid #667eea; }
        .table-actions { white-space: nowrap; }
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
                        <small class="text-light">v1.0</small>
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
                            <?= htmlspecialchars($success_message) ?>
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
                            
                            <div class="col-md-3 mb-3">
                                <div class="card stat-card">
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <div>
                                                <p class="card-title text-muted mb-1">Dominios Únicos</p>
                                                <h3 class="mb-0"><?= $stats['unique_domains'] ?? 0 ?></h3>
                                            </div>
                                            <div class="text-warning">
                                                <i class="fas fa-globe fa-2x"></i>
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
                                                        <th>Clave</th>
                                                        <th>Estado</th>
                                                        <th>Fecha</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <?php foreach ($recent_licenses as $license): ?>
                                                        <tr>
                                                            <td><?= htmlspecialchars($license['client_name']) ?></td>
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
                                                            <td><?= date('d/m/Y', strtotime($license['created_at'])) ?></td>
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
                                                                <strong><?= htmlspecialchars($log['client_name']) ?></strong><br>
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
                                                <th>Email</th>
                                                <th>Clave de Licencia</th>
                                                <th>Tipo</th>
                                                <th>Estado</th>
                                                <th>Expira</th>
                                                <th>Activaciones</th>
                                                <th>Acciones</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                            $all_licenses = $licenseManager->getLicenses(100);
                                            foreach ($all_licenses as $license): 
                                            ?>
                                                <tr>
                                                    <td><?= htmlspecialchars($license['client_name']) ?></td>
                                                    <td><?= htmlspecialchars($license['client_email']) ?></td>
                                                    <td><code><?= htmlspecialchars($license['license_key']) ?></code></td>
                                                    <td><?= ucfirst($license['license_type']) ?></td>
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
                                                        <?= $license['expires_at'] ? date('d/m/Y', strtotime($license['expires_at'])) : 'Permanente' ?>
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
                                                    <td colspan="9" class="text-center py-4">
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
        <div class="modal-dialog modal-lg">
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
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="client_name" class="form-label">Nombre del Cliente</label>
                                    <input type="text" class="form-control" name="client_name" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="client_email" class="form-label">Email del Cliente</label>
                                    <input type="email" class="form-control" name="client_email" required>
                                </div>
                            </div>
                        </div>
                        
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
                        
                        <div class="mb-3">
                            <label for="expires_at" class="form-label">Fecha de Expiración (opcional)</label>
                            <input type="datetime-local" class="form-control" name="expires_at">
                            <div class="form-text">Dejar vacío para licencia permanente</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="notes" class="form-label">Notas</label>
                            <textarea class="form-control" name="notes" rows="3"></textarea>
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
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function editLicense(id) {
            // Implementar edición de licencia
            alert('Función de edición - ID: ' + id);
        }
        
        function viewActivations(id) {
            // Ver activaciones de una licencia
            window.location.href = '?tab=activations&license=' + id;
        }
        
        function deleteLicense(id, clientName) {
            if (confirm('¿Estás seguro de eliminar la licencia de "' + clientName + '"?\n\nEsta acción no se puede deshacer.')) {
                // Crear formulario para eliminar
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = '<input type="hidden" name="delete_license" value="1"><input type="hidden" name="license_id" value="' + id + '">';
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function viewActivationDetails(activationId) {
            // Mostrar detalles de activación
            fetch('api_admin.php?action=get_activation_details&id=' + activationId)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showActivationModal(data.activation);
                    } else {
                        alert('Error al cargar detalles: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('Error de conexión');
                });
        }
        
        function showActivationModal(activation) {
            let modalHTML = `
                <div class="modal fade" id="activationDetailsModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">
                                    <i class="fas fa-info-circle me-2"></i>Detalles de Activación
                                </h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <strong>Dominio:</strong> ${activation.domain}<br>
                                        <strong>IP:</strong> ${activation.ip_address}<br>
                                        <strong>Estado:</strong> <span class="badge bg-success">${activation.status}</span><br>
                                        <strong>Activada:</strong> ${activation.activated_at}
                                    </div>
                                    <div class="col-md-6">
                                        <strong>Última verificación:</strong> ${activation.last_check}<br>
                                        <strong>Total verificaciones:</strong> ${activation.check_count}<br>
                                        <strong>User Agent:</strong><br>
                                        <small class="text-muted">${activation.user_agent || 'No disponible'}</small>
                                    </div>
                                </div>
                                ${activation.server_info ? `
                                <hr>
                                <h6>Información del Servidor</h6>
                                <pre class="bg-light p-2 rounded">${JSON.stringify(JSON.parse(activation.server_info), null, 2)}</pre>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Eliminar modal anterior si existe
            const existingModal = document.getElementById('activationDetailsModal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Agregar nuevo modal
            document.body.insertAdjacentHTML('beforeend', modalHTML);
            
            // Mostrar modal
            const modal = new bootstrap.Modal(document.getElementById('activationDetailsModal'));
            modal.show();
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
        
        // Función para generar múltiples licencias
        function generateBulkLicenses() {
            const quantity = prompt('¿Cuántas licencias desea generar?', '5');
            if (quantity && parseInt(quantity) > 0) {
                if (confirm(`¿Generar ${quantity} licencias con configuración predeterminada?`)) {
                    window.open('bulk_generator.php?quantity=' + quantity, '_blank');
                }
            }
        }
        
        // Auto-refresh para estadísticas cada 30 segundos
        if (window.location.search.includes('tab=dashboard') || !window.location.search.includes('tab=')) {
            setInterval(function() {
                // Solo actualizar si estamos en dashboard y no hay modales abiertos
                if (document.querySelectorAll('.modal.show').length === 0) {
                    fetch('api_admin.php?action=get_stats')
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                updateDashboardStats(data.stats);
                            }
                        })
                        .catch(error => console.log('Error actualizando stats'));
                }
            }, 30000);
        }
        
        function updateDashboardStats(stats) {
            // Actualizar estadísticas en tiempo real
            const statElements = {
                'total_licenses': stats.total_licenses,
                'active_licenses': stats.active_licenses,
                'total_activations': stats.total_activations,
                'unique_domains': stats.unique_domains
            };
            
            Object.keys(statElements).forEach(key => {
                const element = document.querySelector(`[data-stat="${key}"]`);
                if (element) {
                    element.textContent = statElements[key];
                }
            });
        }
    </script>
</body>
</html>