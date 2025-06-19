// =====================================================================
// ARCHIVO 2: whatsapp_notifier.php (para cron job)
// =====================================================================

<?php
// Configurar zona horaria
date_default_timezone_set('America/Bogota');

// Incluir archivos necesarios
require_once __DIR__ . '/whatsapp_config.php';
require_once __DIR__ . '/LicenseManager.class.php';

// Configuración de la base de datos
$license_db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj',
    'database' => 'serverbussn_sdcode'
];

class WhatsAppNotifier {
    private $licenseManager;
    private $config;
    
    public function __construct($db_config, $whatsapp_config) {
        $this->licenseManager = new LicenseManager($db_config, $whatsapp_config);
        $this->config = $whatsapp_config;
    }
    
    public function run() {
        $this->log("=== INICIANDO VERIFICACIÓN DE LICENCIAS ===");
        
        if (!$this->config['enabled']) {
            $this->log("WhatsApp está desactivado en la configuración");
            return;
        }
        
        try {
            // Verificar licencias por expirar y expiradas
            $notified_count = $this->licenseManager->checkExpiringLicensesAndNotify();
            
            $this->log("=== RESUMEN ===");
            $this->log("Total notificaciones enviadas: $notified_count");
            
            return $notified_count;
            
        } catch (Exception $e) {
            $this->log("ERROR: " . $e->getMessage());
            error_log("WhatsApp Notifier Error: " . $e->getMessage());
            return false;
        }
    }
    
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $log_message = "[$timestamp] $message";
        echo $log_message . "\n";
        
        // También escribir a archivo de log si es posible
        $log_dir = __DIR__ . '/logs';
        if (!is_dir($log_dir)) {
            @mkdir($log_dir, 0755, true);
        }
        
        $log_file = $log_dir . '/whatsapp.log';
        @file_put_contents($log_file, $log_message . "\n", FILE_APPEND | LOCK_EX);
    }
}

// EJECUTAR NOTIFICADOR
if (php_sapi_name() === 'cli' || (isset($_GET['run']) && $_GET['run'] === 'notifier')) {
    $notifier = new WhatsAppNotifier($license_db_config, $whatsapp_config);
    $result = $notifier->run();
    
    if (php_sapi_name() !== 'cli') {
        echo "<pre>";
        echo "Notificador ejecutado. Resultado: " . ($result !== false ? "$result mensajes enviados" : "Error");
        echo "</pre>";
    }
}
?>

