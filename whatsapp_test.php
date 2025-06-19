<?php
/**
 * Panel de Pruebas WhatsApp para Whaticket
 */

require_once 'whatsapp_config.php';
require_once 'LicenseManager.class.php';

// Configuración de la base de datos
$license_db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj',
    'database' => 'serverbussn_sdcode'
];

$test_result = null;
$error_message = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $phone = $_POST['phone'] ?? '';
    $type = $_POST['type'] ?? 'license_created';
    $custom_message = $_POST['custom_message'] ?? '';
    
    if (empty($phone)) {
        $error_message = "Número de teléfono requerido";
    } else {
        try {
            $licenseManager = new LicenseManager($license_db_config, $whatsapp_config);
            
            if ($type === 'custom' && !empty($custom_message)) {
                // Envío de mensaje personalizado
                $success = $licenseManager->sendWhatsAppMessage($phone, $custom_message, 'test');
                $test_result = $success ? "Mensaje personalizado enviado exitosamente" : "Error enviando mensaje personalizado";
            } else {
                // Usar templates predefinidos
                $test_data = [
                    'client_name' => 'Cliente de Prueba',
                    'client_phone' => $phone,
                    'license_key' => 'LC-TEST-' . date('md') . '-' . rand(1000, 9999),
                    'expires_at' => date('Y-m-d H:i:s', strtotime('+30 days')),
                    'days_remaining' => 3,
                    'old_status' => 'suspended',
                    'new_status' => 'active',
                    'product_name' => 'Sistema de Códigos',
                    'domain' => 'test.ejemplo.com'
                ];
                
                $success = $licenseManager->sendWhatsAppNotification($type, $test_data);
                $test_result = $success ? "Mensaje de prueba enviado exitosamente" : "Error enviando mensaje";
            }
            
        } catch (Exception $e) {
            $error_message = "Error: " . $e->getMessage();
        }
    }
}

// Obtener logs recientes
$recent_logs = [];
try {
    $conn = new mysqli($license_db_config['host'], $license_db_config['username'], 
                     $license_db_config['password'], $license_db_config['database']);
    
    $result = $conn->query("SELECT * FROM whatsapp_logs ORDER BY sent_at DESC LIMIT 15");
    if ($result) {
        $recent_logs = $result->fetch_all(MYSQLI_ASSOC);
    }
    $conn->close();
} catch (Exception $e) {
    // Ignorar errores de logs
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prueba WhatsApp - Whaticket</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .message-preview {
            background: #f8f9fa;
            border-left: 4px solid #25D366;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            white-space: pre-line;
        }
        .whatsapp-green { color: #25D366; }
        .status-200 { color: #28a745; }
        .status-error { color: #dc3545; }
    </style>
</head>
<body class="bg-light">
    <div class="container py-4">
        <div class="row">
            <div class="col-md-8">
                <div class="card shadow">
                    <div class="card-header bg-success text-white">
                        <h4 class="mb-0">
                            <i class="fab fa-whatsapp me-2"></i>
                            Prueba WhatsApp - Whaticket
                        </h4>
                        <small>Sistema de Licencias - Test Panel</small>
                    </div>
                    <div class="card-body">
                        <?php if ($test_result): ?>
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle me-2"></i>
                                <?= htmlspecialchars($test_result) ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($error_message): ?>
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                <?= htmlspecialchars($error_message) ?>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST" id="testForm">
                            <div class="mb-3">
                                <label for="phone" class="form-label">
                                    <i class="fas fa-phone me-2"></i>Número de Teléfono
                                </label>
                                <input type="text" class="form-control" name="phone" 
                                       placeholder="573001234567 o 3001234567" 
                                       value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>" required>
                                <div class="form-text">Solo números. Código de país opcional (se asume +57 para Colombia)</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="type" class="form-label">
                                    <i class="fas fa-comments me-2"></i>Tipo de Mensaje
                                </label>
                                <select class="form-select" name="type" id="messageType" onchange="toggleCustomMessage()">
                                    <option value="license_created">🎉 Licencia Creada</option>
                                    <option value="expiring_soon">⚠️ Por Expirar (3 días)</option>
                                    <option value="status_changed">🔄 Cambio de Estado</option>
                                    <option value="license_expired">🚫 Licencia Expirada</option>
                                    <option value="license_activated">✅ Licencia Activada en Dominio</option>
                                    <option value="custom">✏️ Mensaje Personalizado</option>
                                </select>
                            </div>
                            
                            <div class="mb-3" id="customMessageDiv" style="display: none;">
                                <label for="custom_message" class="form-label">
                                    <i class="fas fa-edit me-2"></i>Mensaje Personalizado
                                </label>
                                <textarea class="form-control" name="custom_message" rows="4" 
                                          placeholder="Escribe tu mensaje personalizado aquí..."></textarea>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-eye me-2"></i>Vista Previa del Mensaje
                                </label>
                                <div class="message-preview" id="messagePreview">
                                    Selecciona un tipo de mensaje para ver la vista previa...
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex">
                                <button type="submit" class="btn btn-success btn-lg me-md-2">
                                    <i class="fab fa-whatsapp me-2"></i>
                                    Enviar Mensaje de Prueba
                                </button>
                                
                                <a href="?run=notifier" class="btn btn-warning btn-lg">
                                    <i class="fas fa-bell me-2"></i>
                                    Ejecutar Notificador Manual
                                </a>
                                
                                <a href="Psnel_administracion.php" class="btn btn-secondary btn-lg">
                                    <i class="fas fa-arrow-left me-2"></i>
                                    Volver al Panel
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <!-- Configuración actual -->
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-cog me-2"></i>Configuración Whaticket
                        </h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-unstyled mb-0">
                            <li><strong>Estado:</strong> 
                                <?php if ($whatsapp_config['enabled']): ?>
                                    <span class="badge bg-success">✅ Activado</span>
                                <?php else: ?>
                                    <span class="badge bg-danger">❌ Desactivado</span>
                                <?php endif; ?>
                            </li>
                            <li class="mt-2"><strong>Endpoint:</strong><br>
                                <small class="text-muted"><?= htmlspecialchars($whatsapp_config['endpoint']) ?></small>
                            </li>
                            <li class="mt-2"><strong>Token:</strong><br>
                                <small class="text-muted"><?= substr($whatsapp_config['token'], 0, 10) ?>...<?= substr($whatsapp_config['token'], -4) ?></small>
                            </li>
                            <li class="mt-2"><strong>Alerta (días):</strong> <?= $whatsapp_config['expiry_alert_days'] ?></li>
                            <li><strong>Verificación:</strong> <?= $whatsapp_config['daily_check_hour'] ?></li>
                            <li><strong>Empresa:</strong> <?= htmlspecialchars($whatsapp_config['company_name']) ?></li>
                        </ul>
                    </div>
                </div>
                
                <!-- Logs recientes -->
                <div class="card mt-3">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-history me-2"></i>Logs Recientes
                        </h5>
                    </div>
                    <div class="card-body p-0" style="max-height: 400px; overflow-y: auto;">
                        <?php if (!empty($recent_logs)): ?>
                            <div class="list-group list-group-flush">
                                <?php foreach ($recent_logs as $log): ?>
                                    <div class="list-group-item">
                                        <div class="d-flex justify-content-between">
                                            <small class="text-muted"><?= date('d/m H:i', strtotime($log['sent_at'])) ?></small>
                                            <span class="badge <?= $log['http_code'] >= 200 && $log['http_code'] < 300 ? 'bg-success' : 'bg-danger' ?>">
                                                <?= $log['http_code'] ?>
                                            </span>
                                        </div>
                                        <div><strong><?= htmlspecialchars($log['phone']) ?></strong></div>
                                        <div class="text-muted">
                                            <small><?= htmlspecialchars($log['type']) ?></small>
                                        </div>
                                        <?php if ($log['http_code'] < 200 || $log['http_code'] >= 300): ?>
                                            <div class="text-danger">
                                                <small><?= htmlspecialchars(substr($log['response'], 0, 50)) ?>...</small>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <div class="p-3 text-center text-muted">
                                <i class="fas fa-inbox fa-2x mb-2"></i><br>
                                No hay logs disponibles
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
    // Plantillas de mensajes para vista previa
    const messageTemplates = {
        'license_created': `🎉 *¡Licencia Activada!*

Hola *Cliente de Prueba*,

Tu licencia de Sistema de Códigos ha sido activada exitosamente:

🔑 *Clave de Licencia:*
\`LC-TEST-${String(new Date().getMonth()+1).padStart(2,'0')}${String(new Date().getDate()).padStart(2,'0')}-${Math.floor(Math.random()*9000)+1000}\`

📅 *Válida hasta:* ${new Date(Date.now() + 30*24*60*60*1000).toLocaleDateString('es-ES')}
🏢 *Producto:* Sistema de Códigos

✅ Ya puedes utilizar tu licencia.

_¡Gracias por confiar en nosotros!_`,

        'expiring_soon': `⚠️ *¡Atención! Licencia por Expirar*

Hola *Cliente de Prueba*,

Tu licencia de Sistema de Códigos expirará en *3 días*:

🔑 *Clave:* \`LC-TEST-${String(new Date().getMonth()+1).padStart(2,'0')}${String(new Date().getDate()).padStart(2,'0')}-${Math.floor(Math.random()*9000)+1000}\`
📅 *Expira:* ${new Date(Date.now() + 3*24*60*60*1000).toLocaleDateString('es-ES')}
🏢 *Producto:* Sistema de Códigos

🔄 *¡Renueva ahora para evitar interrupciones!*

Contáctanos para procesar tu renovación.`,

        'status_changed': `🔄 *Estado de Licencia Actualizado*

Hola *Cliente de Prueba*,

El estado de tu licencia ha sido modificado:

🔑 *Clave:* \`LC-TEST-${String(new Date().getMonth()+1).padStart(2,'0')}${String(new Date().getDate()).padStart(2,'0')}-${Math.floor(Math.random()*9000)+1000}\`
📊 *Estado anterior:* Suspended
📊 *Estado actual:* *Active*
🏢 *Producto:* Sistema de Códigos

✅ Tu licencia está ahora *ACTIVA* y funcionando.

Si tienes dudas, no dudes en contactarnos.`,

        'license_expired': `🚫 *Licencia Expirada*

Hola *Cliente de Prueba*,

Tu licencia de Sistema de Códigos ha expirado:

🔑 *Clave:* \`LC-TEST-${String(new Date().getMonth()+1).padStart(2,'0')}${String(new Date().getDate()).padStart(2,'0')}-${Math.floor(Math.random()*9000)+1000}\`
📅 *Expiró:* ${new Date().toLocaleDateString('es-ES')}
🏢 *Producto:* Sistema de Códigos

⛔ *El acceso ha sido suspendido.*

🔄 Contáctanos inmediatamente para renovar y recuperar el acceso.`,

        'license_activated': `✅ *¡Licencia Reactivada!*

Hola *Cliente de Prueba*,

Tu licencia ha sido reactivada en el dominio:

🔑 *Clave:* \`LC-TEST-${String(new Date().getMonth()+1).padStart(2,'0')}${String(new Date().getDate()).padStart(2,'0')}-${Math.floor(Math.random()*9000)+1000}\`
🌐 *Dominio:* test.ejemplo.com
📅 *Válida hasta:* ${new Date(Date.now() + 30*24*60*60*1000).toLocaleDateString('es-ES')}

✅ El sistema ya está funcionando normalmente.

_Gracias por usar Sistema de Códigos_`
    };

    function toggleCustomMessage() {
        const type = document.getElementById('messageType').value;
        const customDiv = document.getElementById('customMessageDiv');
        const preview = document.getElementById('messagePreview');
        
        if (type === 'custom') {
            customDiv.style.display = 'block';
            preview.textContent = 'Escribe tu mensaje personalizado arriba...';
        } else {
            customDiv.style.display = 'none';
            preview.textContent = messageTemplates[type] || 'Mensaje no disponible';
        }
    }

    // Inicializar vista previa
    document.addEventListener('DOMContentLoaded', function() {
        toggleCustomMessage();
    });
    </script>
</body>
</html>

<?php
// Manejar ejecución del notificador manual
if (isset($_GET['run']) && $_GET['run'] === 'notifier') {
    echo "<div class='container mt-4'><div class='card'><div class='card-body'>";
    echo "<h5>Ejecutando Notificador Manual...</h5><pre>";
    
    try {
        $licenseManager = new LicenseManager($license_db_config, $whatsapp_config);
        $result = $licenseManager->checkExpiringLicensesAndNotify();
        echo "Notificador ejecutado exitosamente.\n";
        echo "Notificaciones enviadas: $result\n";
    } catch (Exception $e) {
        echo "Error ejecutando notificador: " . $e->getMessage() . "\n";
    }
    
    echo "</pre><a href='whatsapp_test.php' class='btn btn-primary'>Volver</a>";
    echo "</div></div></div>";
}
?>