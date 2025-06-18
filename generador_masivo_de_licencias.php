<?php
/**
 * Generador Masivo de Licencias
 * Herramienta para crear múltiples licencias de forma automática
 */

session_start();
require_once 'license_admin_panel.php'; // Reutilizar la clase LicenseManager

// Verificar autenticación
if (!$licenseManager->isLoggedIn()) {
    header('Location: license_admin_panel.php');
    exit;
}

$current_action = $_GET['action'] ?? 'form';
$quantity = (int)($_GET['quantity'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_bulk'])) {
    $bulk_config = [
        'quantity' => (int)$_POST['quantity'],
        'license_type' => $_POST['license_type'],
        'max_domains' => (int)$_POST['max_domains'],
        'expires_days' => $_POST['expires_days'] ? (int)$_POST['expires_days'] : null,
        'client_prefix' => trim($_POST['client_prefix']),
        'product_name' => trim($_POST['product_name']),
        'version' => trim($_POST['version']),
        'notes' => trim($_POST['notes'])
    ];
    
    $generated_licenses = generateBulkLicenses($bulk_config);
    $current_action = 'results';
}

function generateBulkLicenses($config) {
    global $licenseManager;
    
    $licenses = [];
    $errors = [];
    
    for ($i = 1; $i <= $config['quantity']; $i++) {
        $license_data = [
            'client_name' => $config['client_prefix'] . ' #' . str_pad($i, 3, '0', STR_PAD_LEFT),
            'client_email' => strtolower(str_replace(' ', '', $config['client_prefix'])) . $i . '@temp-email.com',
            'product_name' => $config['product_name'],
            'version' => $config['version'],
            'license_type' => $config['license_type'],
            'max_domains' => $config['max_domains'],
            'expires_at' => $config['expires_days'] ? date('Y-m-d H:i:s', time() + ($config['expires_days'] * 24 * 3600)) : null,
            'notes' => $config['notes'] . " (Generada automáticamente #$i)"
        ];
        
        $result = $licenseManager->createLicense($license_data);
        
        if ($result['success']) {
            $licenses[] = [
                'number' => $i,
                'license_key' => $result['license_key'],
                'client_name' => $license_data['client_name']
            ];
        } else {
            $errors[] = "Error en licencia #$i: " . $result['error'];
        }
    }
    
    return [
        'licenses' => $licenses,
        'errors' => $errors,
        'config' => $config
    ];
}

function exportLicensesToCSV($licenses, $config) {
    $filename = 'licenses_bulk_' . date('Y-m-d_H-i') . '.csv';
    
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    
    // Encabezados CSV
    fputcsv($output, [
        'Número',
        'Clave de Licencia',
        'Cliente',
        'Tipo',
        'Dominios Máximos',
        'Expira',
        'Producto',
        'Versión',
        'Notas'
    ]);
    
    // Datos
    foreach ($licenses as $license) {
        fputcsv($output, [
            $license['number'],
            $license['license_key'],
            $license['client_name'],
            $config['license_type'],
            $config['max_domains'],
            $config['expires_days'] ? $config['expires_days'] . ' días' : 'Permanente',
            $config['product_name'],
            $config['version'],
            $config['notes']
        ]);
    }
    
    fclose($output);
    exit;
}

// Manejar exportación
if ($current_action === 'export' && isset($_SESSION['last_bulk_generation'])) {
    exportLicensesToCSV(
        $_SESSION['last_bulk_generation']['licenses'],
        $_SESSION['last_bulk_generation']['config']
    );
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generador Masivo de Licencias</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .generator-card { background: rgba(255, 255, 255, 0.95); border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .license-key { font-family: 'Courier New', monospace; font-size: 0.9rem; }
        .progress-container { display: none; }
    </style>
</head>
<body class="py-4">
    <div class="container">
        <!-- Header -->
        <div class="text-center mb-4">
            <div class="generator-card p-4 mx-auto" style="max-width: 600px;">
                <i class="fas fa-magic fa-3x text-primary mb-3"></i>
                <h1 class="h2 text-dark">Generador Masivo de Licencias</h1>
                <p class="text-muted">Crea múltiples licencias de forma automática</p>
                <a href="license_admin_panel.php" class="btn btn-outline-secondary">
                    <i class="fas fa-arrow-left me-2"></i>Volver al Panel
                </a>
            </div>
        </div>

        <?php if ($current_action === 'form'): ?>
            <!-- Formulario de generación -->
            <div class="generator-card p-4 mx-auto" style="max-width: 800px;">
                <form method="POST" id="bulkForm">
                    <div class="row">
                        <!-- Configuración básica -->
                        <div class="col-md-6">
                            <h5 class="mb-3">
                                <i class="fas fa-cog me-2 text-info"></i>Configuración Básica
                            </h5>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-hashtag me-2"></i>Cantidad de Licencias
                                </label>
                                <input type="number" class="form-control" name="quantity" 
                                       value="<?= $quantity > 0 ? $quantity : 5 ?>" min="1" max="100" required>
                                <div class="form-text">Máximo 100 licencias por lote</div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-user me-2"></i>Prefijo del Cliente
                                </label>
                                <input type="text" class="form-control" name="client_prefix" 
                                       value="Cliente" placeholder="Cliente, Empresa, Usuario..." required>
                                <div class="form-text">Se numerarán automáticamente: Prefijo #001, #002...</div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-certificate me-2"></i>Tipo de Licencia
                                </label>
                                <select class="form-select" name="license_type" required>
                                    <option value="single">Single Domain (1 dominio)</option>
                                    <option value="multiple">Multiple Domains</option>
                                    <option value="unlimited">Unlimited Domains</option>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-globe me-2"></i>Dominios Máximos
                                </label>
                                <input type="number" class="form-control" name="max_domains" 
                                       value="1" min="1" max="999" required>
                            </div>
                        </div>
                        
                        <!-- Configuración avanzada -->
                        <div class="col-md-6">
                            <h5 class="mb-3">
                                <i class="fas fa-sliders-h me-2 text-warning"></i>Configuración Avanzada
                            </h5>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-calendar me-2"></i>Días de Expiración
                                </label>
                                <input type="number" class="form-control" name="expires_days" 
                                       placeholder="Dejar vacío para permanente" min="1" max="3650">
                                <div class="form-text">Vacío = licencia permanente</div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-box me-2"></i>Producto
                                </label>
                                <input type="text" class="form-control" name="product_name" 
                                       value="Sistema de Códigos" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-code-branch me-2"></i>Versión
                                </label>
                                <input type="text" class="form-control" name="version" 
                                       value="1.0" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-sticky-note me-2"></i>Notas
                                </label>
                                <textarea class="form-control" name="notes" rows="2" 
                                          placeholder="Notas adicionales para las licencias...">Generación masiva - <?= date('Y-m-d') ?></textarea>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Resumen -->
                    <div class="alert alert-info mt-3">
                        <h6><i class="fas fa-info-circle me-2"></i>Resumen de Generación</h6>
                        <div id="generation-summary">
                            Se generarán <strong><span id="summary-quantity">5</span></strong> licencias del tipo 
                            <strong><span id="summary-type">single</span></strong> con un máximo de 
                            <strong><span id="summary-domains">1</span></strong> dominio(s) cada una.
                        </div>
                    </div>
                    
                    <!-- Botones -->
                    <div class="text-center mt-4">
                        <button type="submit" name="generate_bulk" class="btn btn-success btn-lg">
                            <i class="fas fa-magic me-2"></i>Generar Licencias
                        </button>
                    </div>
                </form>
                
                <!-- Progreso -->
                <div class="progress-container mt-4">
                    <div class="text-center mb-3">
                        <i class="fas fa-spinner fa-spin fa-2x text-primary"></i>
                        <h5 class="mt-2">Generando Licencias...</h5>
                    </div>
                    <div class="progress">
                        <div class="progress-bar progress-bar-striped progress-bar-animated" 
                             role="progressbar" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
        <?php elseif ($current_action === 'results'): ?>
            <!-- Resultados de generación -->
            <div class="generator-card p-4 mx-auto" style="max-width: 1200px;">
                <div class="text-center mb-4">
                    <i class="fas fa-check-circle fa-4x text-success mb-3"></i>
                    <h2 class="text-success">¡Generación Completada!</h2>
                    <p class="text-muted">Se han generado <?= count($generated_licenses['licenses']) ?> licencias</p>
                </div>
                
                <!-- Estadísticas -->
                <div class="row mb-4">
                    <div class="col-md-4">
                        <div class="card border-success">
                            <div class="card-body text-center">
                                <i class="fas fa-check-circle fa-2x text-success mb-2"></i>
                                <h4 class="text-success"><?= count($generated_licenses['licenses']) ?></h4>
                                <p class="mb-0">Licencias Generadas</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card border-danger">
                            <div class="card-body text-center">
                                <i class="fas fa-exclamation-triangle fa-2x text-danger mb-2"></i>
                                <h4 class="text-danger"><?= count($generated_licenses['errors']) ?></h4>
                                <p class="mb-0">Errores</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card border-info">
                            <div class="card-body text-center">
                                <i class="fas fa-percentage fa-2x text-info mb-2"></i>
                                <h4 class="text-info"><?= round((count($generated_licenses['licenses']) / $generated_licenses['config']['quantity']) * 100, 1) ?>%</h4>
                                <p class="mb-0">Tasa de Éxito</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Errores -->
                <?php if (!empty($generated_licenses['errors'])): ?>
                    <div class="alert alert-danger">
                        <h6><i class="fas fa-exclamation-triangle me-2"></i>Errores Durante la Generación</h6>
                        <ul class="mb-0">
                            <?php foreach ($generated_licenses['errors'] as $error): ?>
                                <li><?= htmlspecialchars($error) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                
                <!-- Acciones -->
                <div class="text-center mb-4">
                    <div class="btn-group" role="group">
                        <a href="?action=export" class="btn btn-success">
                            <i class="fas fa-download me-2"></i>Exportar CSV
                        </a>
                        <a href="license_admin_panel.php?tab=licenses" class="btn btn-primary">
                            <i class="fas fa-list me-2"></i>Ver en Panel Admin
                        </a>
                        <a href="?" class="btn btn-secondary">
                            <i class="fas fa-plus me-2"></i>Generar Más
                        </a>
                    </div>
                </div>
                
                <!-- Lista de licencias generadas -->
                <h5 class="mb-3">
                    <i class="fas fa-list me-2"></i>Licencias Generadas
                </h5>
                <div class="table-responsive">
                    <table class="table table-hover table-sm">
                        <thead class="table-dark">
                            <tr>
                                <th>#</th>
                                <th>Clave de Licencia</th>
                                <th>Cliente</th>
                                <th>Tipo</th>
                                <th>Dominios</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($generated_licenses['licenses'] as $license): ?>
                                <tr>
                                    <td><?= $license['number'] ?></td>
                                    <td>
                                        <code class="license-key"><?= htmlspecialchars($license['license_key']) ?></code>
                                        <button class="btn btn-sm btn-outline-secondary ms-2" 
                                                onclick="copyToClipboard('<?= $license['license_key'] ?>')">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </td>
                                    <td><?= htmlspecialchars($license['client_name']) ?></td>
                                    <td>
                                        <span class="badge bg-info"><?= ucfirst($generated_licenses['config']['license_type']) ?></span>
                                    </td>
                                    <td><?= $generated_licenses['config']['max_domains'] ?></td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary" 
                                                onclick="showLicenseDetails('<?= $license['license_key'] ?>')">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <?php 
                // Guardar en sesión para exportación
                $_SESSION['last_bulk_generation'] = $generated_licenses;
                ?>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Actualizar resumen en tiempo real
        function updateSummary() {
            document.getElementById('summary-quantity').textContent = 
                document.querySelector('[name="quantity"]').value || '0';
            document.getElementById('summary-type').textContent = 
                document.querySelector('[name="license_type"]').value || 'single';
            document.getElementById('summary-domains').textContent = 
                document.querySelector('[name="max_domains"]').value || '1';
        }
        
        // Event listeners
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('bulkForm');
            const progressContainer = document.querySelector('.progress-container');
            
            if (form) {
                // Actualizar resumen al cambiar valores
                form.addEventListener('change', updateSummary);
                form.addEventListener('input', updateSummary);
                
                // Mostrar progreso al enviar
                form.addEventListener('submit', function() {
                    progressContainer.style.display = 'block';
                    simulateProgress();
                });
            }
            
            updateSummary();
        });
        
        function simulateProgress() {
            const progressBar = document.querySelector('.progress-bar');
            let width = 0;
            const interval = setInterval(function() {
                width += Math.random() * 30;
                if (width >= 90) width = 90;
                progressBar.style.width = width + '%';
                
                if (width >= 90) {
                    clearInterval(interval);
                    // El progreso se completará cuando llegue la respuesta
                }
            }, 200);
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                // Mostrar notificación
                const toast = document.createElement('div');
                toast.className = 'position-fixed top-0 end-0 p-3';
                toast.style.zIndex = '9999';
                toast.innerHTML = `
                    <div class="toast show" role="alert">
                        <div class="toast-header">
                            <i class="fas fa-check-circle text-success me-2"></i>
                            <strong class="me-auto">Copiado</strong>
                        </div>
                        <div class="toast-body">
                            Clave de licencia copiada al portapapeles
                        </div>
                    </div>
                `;
                document.body.appendChild(toast);
                
                setTimeout(() => {
                    document.body.removeChild(toast);
                }, 3000);
            });
        }
        
        function showLicenseDetails(licenseKey) {
            alert('Detalles de licencia: ' + licenseKey + '\n\nEsta función se puede expandir para mostrar más información.');
        }
    </script>
</body>
</html>
