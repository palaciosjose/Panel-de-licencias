<?php
/**
 * Generador Masivo de Licencias
 * Herramienta para crear múltiples licencias de forma automática
 * Version 1.1 - Con teléfono y sistema de períodos
 */

session_start();
require_once 'Psnel_administracion.php'; // Reutilizar la clase LicenseManager

// Verificar autenticación
if (!$licenseManager->isLoggedIn()) {
    header('Location: Psnel_administracion.php');
    exit;
}

$current_action = $_GET['action'] ?? 'form';
$quantity = (int)($_GET['quantity'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_bulk'])) {
    $bulk_config = [
        'quantity' => (int)$_POST['quantity'],
        'license_type' => $_POST['license_type'],
        'max_domains' => (int)$_POST['max_domains'],
        'duration_days' => $_POST['duration_days'] ? (int)$_POST['duration_days'] : null,
        'start_date' => $_POST['start_date'] ?: date('Y-m-d H:i:s'),
        'client_prefix' => trim($_POST['client_prefix']),
        'phone_prefix' => trim($_POST['phone_prefix']),
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
        // Generar teléfono secuencial
        $phone = '';
        if ($config['phone_prefix']) {
            $phone = $config['phone_prefix'] . str_pad($i, 4, '0', STR_PAD_LEFT);
        }
        
        $license_data = [
            'client_name' => $config['client_prefix'] . ' #' . str_pad($i, 3, '0', STR_PAD_LEFT),
            'client_email' => strtolower(str_replace(' ', '', $config['client_prefix'])) . $i . '@temp-email.com',
            'client_phone' => $phone,
            'product_name' => $config['product_name'],
            'version' => $config['version'],
            'license_type' => $config['license_type'],
            'max_domains' => $config['max_domains'],
            'start_date' => $config['start_date'],
            'duration_days' => $config['duration_days'],
            'notes' => $config['notes'] . " (Generada automáticamente #$i)"
        ];
        
        $result = $licenseManager->createLicense($license_data);
        
        if ($result['success']) {
            $licenses[] = [
                'number' => $i,
                'license_key' => $result['license_key'],
                'client_name' => $license_data['client_name'],
                'client_phone' => $license_data['client_phone'],
                'start_date' => $result['start_date'],
                'expires_at' => $result['expires_at']
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
        'Teléfono',
        'Tipo',
        'Dominios Máximos',
        'Fecha Inicio',
        'Duración (días)',
        'Fecha Expiración',
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
            $license['client_phone'] ?: 'N/A',
            $config['license_type'],
            $config['max_domains'],
            $license['start_date'],
            $config['duration_days'] ?: 'Permanente',
            $license['expires_at'] ?: 'Permanente',
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
    <title>Generador Masivo de Licencias v1.1</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .generator-card { background: rgba(255, 255, 255, 0.95); border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .license-key { font-family: 'Courier New', monospace; font-size: 0.9rem; }
        .progress-container { display: none; }
        .period-preview { background: #f8f9fa; border-radius: 8px; padding: 15px; margin-top: 10px; }
    </style>
</head>
<body class="py-4">
    <div class="container">
        <!-- Header -->
        <div class="text-center mb-4">
            <div class="generator-card p-4 mx-auto" style="max-width: 600px;">
                <i class="fas fa-magic fa-3x text-primary mb-3"></i>
                <h1 class="h2 text-dark">Generador Masivo de Licencias</h1>
                <p class="text-muted">Crea múltiples licencias de forma automática con períodos personalizados</p>
                <span class="badge bg-info">v1.1</span>
                <br><br>
                <a href="Psnel_administracion.php" class="btn btn-outline-secondary">
                    <i class="fas fa-arrow-left me-2"></i>Volver al Panel
                </a>
            </div>
        </div>

        <?php if ($current_action === 'form'): ?>
            <!-- Formulario de generación -->
            <div class="generator-card p-4 mx-auto" style="max-width: 1000px;">
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
                                    <i class="fas fa-phone me-2"></i>Prefijo de Teléfono (opcional)
                                </label>
                                <input type="text" class="form-control" name="phone_prefix" 
                                       placeholder="+57300" maxlength="10">
                                <div class="form-text">Ejemplo: +57300 generará +573000001, +573000002, etc.</div>
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
                        
                        <!-- Configuración de período -->
                        <div class="col-md-6">
                            <h5 class="mb-3">
                                <i class="fas fa-calendar-alt me-2 text-warning"></i>Configuración de Período
                            </h5>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-play me-2"></i>Fecha de Inicio
                                </label>
                                <input type="datetime-local" class="form-control" name="start_date" 
                                       value="<?= date('Y-m-d\TH:i') ?>" required>
                                <div class="form-text">Cuándo comienzan a ser válidas las licencias</div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-hourglass-half me-2"></i>Duración
                                </label>
                                <select class="form-select" name="duration_days" id="duration_days">
                                    <option value="">Permanente</option>
                                    <option value="7">7 días (Prueba)</option>
                                    <option value="15">15 días (Demo)</option>
                                    <option value="30">30 días (1 mes)</option>
                                    <option value="90">90 días (3 meses)</option>
                                    <option value="180">180 días (6 meses)</option>
                                    <option value="365">365 días (1 año)</option>
                                    <option value="730">730 días (2 años)</option>
                                    <option value="custom">Personalizado...</option>
                                </select>
                            </div>
                            
                            <div class="mb-3" id="custom_duration_container" style="display: none;">
                                <label class="form-label">
                                    <i class="fas fa-edit me-2"></i>Días personalizados
                                </label>
                                <input type="number" class="form-control" name="custom_duration" 
                                       id="custom_duration" min="1" max="3650">
                            </div>
                            
                            <!-- Vista previa del período -->
                            <div class="period-preview" id="period_preview">
                                <h6><i class="fas fa-eye me-2"></i>Vista Previa del Período</h6>
                                <div id="preview_content">
                                    <small class="text-muted">Selecciona fecha y duración para ver la vista previa</small>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Configuración avanzada -->
                    <div class="row mt-4">
                        <div class="col-12">
                            <h5 class="mb-3">
                                <i class="fas fa-sliders-h me-2 text-success"></i>Configuración del Producto
                            </h5>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-box me-2"></i>Producto
                                </label>
                                <input type="text" class="form-control" name="product_name" 
                                       value="Sistema de Códigos" required>
                            </div>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-code-branch me-2"></i>Versión
                                </label>
                                <input type="text" class="form-control" name="version" 
                                       value="1.0" required>
                            </div>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-sticky-note me-2"></i>Notas
                                </label>
                                <input type="text" class="form-control" name="notes" 
                                       value="Generación masiva - <?= date('Y-m-d') ?>">
                            </div>
                        </div>
                    </div>
                    
                    <!-- Resumen -->
                    <div class="alert alert-info mt-3">
                        <h6><i class="fas fa-info-circle me-2"></i>Resumen de Generación</h6>
                        <div id="generation-summary">
                            <div class="row">
                                <div class="col-md-6">
                                    Se generarán <strong><span id="summary-quantity">5</span></strong> licencias del tipo 
                                    <strong><span id="summary-type">single</span></strong> con un máximo de 
                                    <strong><span id="summary-domains">1</span></strong> dominio(s) cada una.
                                </div>
                                <div class="col-md-6" id="summary-period">
                                    <small class="text-muted">Período: Pendiente de configuración</small>
                                </div>
                            </div>
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
                        <p class="text-muted">Configurando períodos y creando claves de licencia</p>
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
                    <p class="text-muted">Se han generado <?= count($generated_licenses['licenses']) ?> licencias con períodos configurados</p>
                </div>
                
                <!-- Estadísticas -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card border-success">
                            <div class="card-body text-center">
                                <i class="fas fa-check-circle fa-2x text-success mb-2"></i>
                                <h4 class="text-success"><?= count($generated_licenses['licenses']) ?></h4>
                                <p class="mb-0">Licencias Generadas</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card border-info">
                            <div class="card-body text-center">
                                <i class="fas fa-calendar-alt fa-2x text-info mb-2"></i>
                                <h6 class="text-info"><?= $generated_licenses['config']['duration_days'] ?: 'Permanente' ?></h6>
                                <p class="mb-0">Duración</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card border-warning">
                            <div class="card-body text-center">
                                <i class="fas fa-phone fa-2x text-warning mb-2"></i>
                                <h6 class="text-warning"><?= $generated_licenses['config']['phone_prefix'] ? 'Sí' : 'No' ?></h6>
                                <p class="mb-0">Teléfonos</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card border-danger">
                            <div class="card-body text-center">
                                <i class="fas fa-exclamation-triangle fa-2x text-danger mb-2"></i>
                                <h4 class="text-danger"><?= count($generated_licenses['errors']) ?></h4>
                                <p class="mb-0">Errores</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Información del período generado -->
                <div class="alert alert-info">
                    <h6><i class="fas fa-calendar-alt me-2"></i>Información del Período</h6>
                    <div class="row">
                        <div class="col-md-4">
                            <strong>Fecha de Inicio:</strong><br>
                            <?= date('d/m/Y H:i', strtotime($generated_licenses['config']['start_date'])) ?>
                        </div>
                        <div class="col-md-4">
                            <strong>Duración:</strong><br>
                            <?= $generated_licenses['config']['duration_days'] ? $generated_licenses['config']['duration_days'] . ' días' : 'Permanente' ?>
                        </div>
                        <div class="col-md-4">
                            <strong>Fecha de Expiración:</strong><br>
                            <?php if ($generated_licenses['config']['duration_days']): ?>
                                <?php
                                $start = strtotime($generated_licenses['config']['start_date']);
                                $expiry = $start + ($generated_licenses['config']['duration_days'] * 24 * 3600);
                                echo date('d/m/Y H:i', $expiry);
                                ?>
                            <?php else: ?>
                                Nunca expira
                            <?php endif; ?>
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
                        <a href="Psnel_administracion.php?tab=licenses" class="btn btn-primary">
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
                                <th>Teléfono</th>
                                <th>Tipo</th>
                                <th>Período</th>
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
                                        <?php if ($license['client_phone']): ?>
                                            <i class="fas fa-phone me-1"></i>
                                            <?= htmlspecialchars($license['client_phone']) ?>
                                        <?php else: ?>
                                            <small class="text-muted">N/A</small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="badge bg-info"><?= ucfirst($generated_licenses['config']['license_type']) ?></span>
                                    </td>
                                    <td>
                                        <small>
                                            <strong>Inicio:</strong> <?= date('d/m/Y', strtotime($license['start_date'])) ?><br>
                                            <?php if ($license['expires_at']): ?>
                                                <strong>Expira:</strong> <?= date('d/m/Y', strtotime($license['expires_at'])) ?>
                                            <?php else: ?>
                                                <span class="badge bg-success">Permanente</span>
                                            <?php endif; ?>
                                        </small>
                                    </td>
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
        // Manejar duración personalizada
        document.getElementById('duration_days').addEventListener('change', function() {
            const customContainer = document.getElementById('custom_duration_container');
            const customField = document.getElementById('custom_duration');
            
            if (this.value === 'custom') {
                customContainer.style.display = 'block';
                customField.required = true;
            } else {
                customContainer.style.display = 'none';
                customField.required = false;
                customField.value = '';
            }
            updatePeriodPreview();
        });
        
        // Actualizar vista previa del período
        function updatePeriodPreview() {
            const startDate = document.querySelector('[name="start_date"]').value;
            const durationSelect = document.getElementById('duration_days');
            const customDuration = document.getElementById('custom_duration');
            const previewContent = document.getElementById('preview_content');
            
            if (!startDate) {
                previewContent.innerHTML = '<small class="text-muted">Selecciona fecha de inicio</small>';
                return;
            }
            
            let duration = durationSelect.value === 'custom' ? customDuration.value : durationSelect.value;
            const start = new Date(startDate);
            
            let html = `<strong>Inicio:</strong> ${start.toLocaleDateString('es-ES')} ${start.toLocaleTimeString('es-ES', {hour: '2-digit', minute: '2-digit'})}<br>`;
            
            if (duration && duration > 0) {
                const expiry = new Date(start.getTime() + (duration * 24 * 60 * 60 * 1000));
                html += `<strong>Duración:</strong> ${duration} días<br>`;
                html += `<strong>Expira:</strong> ${expiry.toLocaleDateString('es-ES')} ${expiry.toLocaleTimeString('es-ES', {hour: '2-digit', minute: '2-digit'})}`;
                
                // Calcular días restantes desde hoy
                const today = new Date();
                const daysFromNow = Math.ceil((expiry - today) / (1000 * 60 * 60 * 24));
                if (daysFromNow > 0) {
                    html += `<br><small class="text-info">Válida por ${daysFromNow} días desde hoy</small>`;
                } else if (daysFromNow < 0) {
                    html += `<br><small class="text-danger">Ya habría expirado (${Math.abs(daysFromNow)} días atrás)</small>`;
                }
            } else {
                html += `<strong>Duración:</strong> <span class="text-success">Permanente (nunca expira)</span>`;
            }
            
            previewContent.innerHTML = html;
        }
        
        // Actualizar resumen en tiempo real
        function updateSummary() {
            document.getElementById('summary-quantity').textContent = 
                document.querySelector('[name="quantity"]').value || '0';
            document.getElementById('summary-type').textContent = 
                document.querySelector('[name="license_type"]').value || 'single';
            document.getElementById('summary-domains').textContent = 
                document.querySelector('[name="max_domains"]').value || '1';
            
            // Actualizar resumen de período
            const duration = document.getElementById('duration_days').value;
            const customDuration = document.getElementById('custom_duration').value;
            const summaryPeriod = document.getElementById('summary-period');
            
            let periodText = '';
            if (duration === 'custom' && customDuration) {
                periodText = `Período: ${customDuration} días personalizados`;
            } else if (duration) {
                const options = {
                    '7': '7 días (Prueba)',
                    '15': '15 días (Demo)',
                    '30': '30 días (1 mes)',
                    '90': '90 días (3 meses)',
                    '180': '180 días (6 meses)',
                    '365': '365 días (1 año)',
                    '730': '730 días (2 años)'
                };
                periodText = `Período: ${options[duration] || duration + ' días'}`;
            } else {
                periodText = 'Período: Permanente (nunca expira)';
            }
            
            summaryPeriod.innerHTML = `<small class="text-muted">${periodText}</small>`;
        }
        
        // Event listeners
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('bulkForm');
            const progressContainer = document.querySelector('.progress-container');
            
            if (form) {
                // Actualizar resumen y preview al cambiar valores
                form.addEventListener('change', function() {
                    updateSummary();
                    updatePeriodPreview();
                });
                form.addEventListener('input', function() {
                    updateSummary();
                    updatePeriodPreview();
                });
                
                // Mostrar progreso al enviar
                form.addEventListener('submit', function() {
                    progressContainer.style.display = 'block';
                    simulateProgress();
                });
            }
            
            updateSummary();
            updatePeriodPreview();
        });
        
        function simulateProgress() {
            const progressBar = document.querySelector('.progress-bar');
            let width = 0;
            const interval = setInterval(function() {
                width += Math.random() * 20;
                if (width >= 90) width = 90;
                progressBar.style.width = width + '%';
                
                if (width >= 90) {
                    clearInterval(interval);
                }
            }, 300);
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
            // Aquí puedes expandir para mostrar más información
            alert('Detalles de licencia: ' + licenseKey + '\n\nEsta función se puede expandir para mostrar información completa del período, cliente, etc.');
        }
    </script>
</body>
</html>