<?php
/**
 * Script de Migración para Sistema de Licencias v1.1
 * Actualiza la base de datos existente y migra datos
 */

// Configuración de la base de datos
$db_config = [
    'host' => 'localhost',
    'username' => 'serverbussn_sdcode',
    'password' => 'zOcblEcfc7mZS7xj',
    'database' => 'serverbussn_sdcode'
];

class LicenseMigration {
    private $conn;
    private $log = [];
    
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
        $this->log("Conexión a base de datos establecida");
    }
    
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $this->log[] = "[$timestamp] $message";
        echo "[$timestamp] $message\n";
    }
    
    public function checkCurrentVersion() {
        $this->log("=== VERIFICANDO VERSIÓN ACTUAL ===");
        
        // Verificar si existen las nuevas columnas
        $result = $this->conn->query("SHOW COLUMNS FROM licenses LIKE 'client_phone'");
        $has_phone = $result->num_rows > 0;
        
        $result = $this->conn->query("SHOW COLUMNS FROM licenses LIKE 'start_date'");
        $has_start_date = $result->num_rows > 0;
        
        $result = $this->conn->query("SHOW COLUMNS FROM licenses LIKE 'duration_days'");
        $has_duration = $result->num_rows > 0;
        
        if ($has_phone && $has_start_date && $has_duration) {
            $this->log("✅ Base de datos ya está actualizada a v1.1");
            return '1.1';
        } else {
            $this->log("📊 Base de datos versión anterior detectada");
            return '1.0';
        }
    }
    
    public function backupDatabase() {
        $this->log("=== CREANDO RESPALDO DE SEGURIDAD ===");
        
        $backup_file = 'backup_licenses_' . date('Y-m-d_H-i-s') . '.sql';
        
        try {
            // Respaldar tabla de licencias
            $result = $this->conn->query("SELECT * FROM licenses");
            $backup_content = "-- Respaldo de licencias - " . date('Y-m-d H:i:s') . "\n\n";
            
            while ($row = $result->fetch_assoc()) {
                $values = array_map(function($value) {
                    return $value === null ? 'NULL' : "'" . $this->conn->real_escape_string($value) . "'";
                }, array_values($row));
                
                $backup_content .= "INSERT INTO licenses_backup (" . implode(', ', array_keys($row)) . ") VALUES (" . implode(', ', $values) . ");\n";
            }
            
            // Crear tabla de respaldo
            $this->conn->query("CREATE TABLE IF NOT EXISTS licenses_backup AS SELECT * FROM licenses WHERE 1=0");
            $this->conn->query("DELETE FROM licenses_backup"); // Limpiar respaldo anterior
            
            // Ejecutar respaldo
            $statements = explode(';', $backup_content);
            foreach ($statements as $statement) {
                $statement = trim($statement);
                if (!empty($statement) && !str_starts_with($statement, '--')) {
                    $this->conn->query($statement);
                }
            }
            
            $this->log("✅ Respaldo creado en tabla 'licenses_backup'");
            
            // También crear archivo de respaldo
            file_put_contents($backup_file, $backup_content);
            $this->log("✅ Archivo de respaldo creado: $backup_file");
            
            return true;
        } catch (Exception $e) {
            $this->log("❌ Error creando respaldo: " . $e->getMessage());
            return false;
        }
    }
    
    public function updateDatabaseSchema() {
        $this->log("=== ACTUALIZANDO ESQUEMA DE BASE DE DATOS ===");
        
        $queries = [
            // Agregar campo de teléfono
            "ALTER TABLE licenses ADD COLUMN client_phone VARCHAR(20) AFTER client_email",
            
            // Agregar campos de período
            "ALTER TABLE licenses ADD COLUMN start_date DATETIME DEFAULT CURRENT_TIMESTAMP AFTER notes",
            "ALTER TABLE licenses ADD COLUMN duration_days INT DEFAULT NULL AFTER start_date",
            
            // Crear índices para optimizar consultas
            "CREATE INDEX idx_licenses_period ON licenses(start_date, expires_at)",
            "CREATE INDEX idx_licenses_phone ON licenses(client_phone)",
            "CREATE INDEX idx_licenses_status_period ON licenses(status, start_date, expires_at)"
        ];
        
        foreach ($queries as $query) {
            try {
                $this->conn->query($query);
                $this->log("✅ Ejecutado: " . substr($query, 0, 50) . "...");
            } catch (Exception $e) {
                // Ignorar errores de columnas que ya existen
                if (strpos($e->getMessage(), 'Duplicate column name') !== false) {
                    $this->log("⚠️ Columna ya existe: " . substr($query, 0, 50) . "...");
                } else {
                    $this->log("❌ Error: " . $e->getMessage());
                }
            }
        }
        
        return true;
    }
    
    public function migrateExistingData() {
        $this->log("=== MIGRANDO DATOS EXISTENTES ===");
        
        // Obtener licencias sin fecha de inicio
        $result = $this->conn->query("SELECT id, created_at, expires_at FROM licenses WHERE start_date IS NULL OR start_date = '0000-00-00 00:00:00'");
        $licenses_to_update = $result->fetch_all(MYSQLI_ASSOC);
        
        $this->log("📊 Encontradas " . count($licenses_to_update) . " licencias para migrar");
        
        foreach ($licenses_to_update as $license) {
            $license_id = $license['id'];
            $created_at = $license['created_at'];
            $expires_at = $license['expires_at'];
            
            // Usar fecha de creación como fecha de inicio
            $start_date = $created_at;
            $duration_days = null;
            
            // Calcular duración si tiene fecha de expiración
            if ($expires_at && $expires_at !== '0000-00-00 00:00:00') {
                $start_timestamp = strtotime($start_date);
                $expire_timestamp = strtotime($expires_at);
                
                if ($expire_timestamp > $start_timestamp) {
                    $duration_days = round(($expire_timestamp - $start_timestamp) / (24 * 3600));
                }
            }
            
            // Actualizar la licencia
            $stmt = $this->conn->prepare("UPDATE licenses SET start_date = ?, duration_days = ? WHERE id = ?");
            $stmt->bind_param("sii", $start_date, $duration_days, $license_id);
            
            if ($stmt->execute()) {
                $duration_text = $duration_days ? "{$duration_days} días" : "permanente";
                $this->log("✅ Licencia ID $license_id migrada: inicio=$start_date, duración=$duration_text");
            } else {
                $this->log("❌ Error migrando licencia ID $license_id: " . $this->conn->error);
            }
        }
        
        return true;
    }
    
    public function updateViews() {
        $this->log("=== ACTUALIZANDO VISTAS Y ESTADÍSTICAS ===");
        
        // Actualizar vista de estadísticas
        $view_query = "
        CREATE OR REPLACE VIEW license_stats AS
        SELECT 
            COUNT(*) as total_licenses,
            COUNT(CASE WHEN status = 'active' THEN 1 END) as active_licenses,
            COUNT(CASE WHEN status = 'expired' THEN 1 END) as expired_licenses,
            COUNT(CASE WHEN status = 'suspended' THEN 1 END) as suspended_licenses,
            (SELECT COUNT(*) FROM license_activations) as total_activations,
            (SELECT COUNT(DISTINCT domain) FROM license_activations WHERE status = 'active') as unique_domains,
            COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN 1 END) as expired_count,
            COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAY) THEN 1 END) as expiring_soon,
            COUNT(CASE WHEN client_phone IS NOT NULL AND client_phone != '' THEN 1 END) as licenses_with_phone,
            COUNT(CASE WHEN duration_days IS NOT NULL THEN 1 END) as time_limited_licenses,
            COUNT(CASE WHEN duration_days IS NULL THEN 1 END) as permanent_licenses
        FROM licenses";
        
        try {
            $this->conn->query($view_query);
            $this->log("✅ Vista 'license_stats' actualizada con nuevos campos");
        } catch (Exception $e) {
            $this->log("❌ Error actualizando vista: " . $e->getMessage());
        }
        
        return true;
    }
    
    public function validateMigration() {
        $this->log("=== VALIDANDO MIGRACIÓN ===");
        
        $errors = 0;
        
        // Verificar que todas las columnas existen
        $required_columns = ['client_phone', 'start_date', 'duration_days'];
        foreach ($required_columns as $column) {
            $result = $this->conn->query("SHOW COLUMNS FROM licenses LIKE '$column'");
            if ($result->num_rows === 0) {
                $this->log("❌ Columna faltante: $column");
                $errors++;
            } else {
                $this->log("✅ Columna presente: $column");
            }
        }
        
        // Verificar que todas las licencias tienen fecha de inicio
        $result = $this->conn->query("SELECT COUNT(*) as count FROM licenses WHERE start_date IS NULL OR start_date = '0000-00-00 00:00:00'");
        $row = $result->fetch_assoc();
        if ($row['count'] > 0) {
            $this->log("❌ {$row['count']} licencias sin fecha de inicio");
            $errors++;
        } else {
            $this->log("✅ Todas las licencias tienen fecha de inicio");
        }
        
        // Verificar consistencia de duración vs expiración
        $result = $this->conn->query("
            SELECT COUNT(*) as count 
            FROM licenses 
            WHERE expires_at IS NOT NULL 
            AND duration_days IS NULL
        ");
        $row = $result->fetch_assoc();
        if ($row['count'] > 0) {
            $this->log("⚠️ {$row['count']} licencias con expiración pero sin duración (puede ser normal)");
        }
        
        // Verificar vista de estadísticas
        try {
            $result = $this->conn->query("SELECT * FROM license_stats LIMIT 1");
            if ($result) {
                $stats = $result->fetch_assoc();
                $this->log("✅ Vista de estadísticas funcional:");
                $this->log("   - Total licencias: {$stats['total_licenses']}");
                $this->log("   - Con teléfono: {$stats['licenses_with_phone']}");
                $this->log("   - Limitadas en tiempo: {$stats['time_limited_licenses']}");
                $this->log("   - Permanentes: {$stats['permanent_licenses']}");
            }
        } catch (Exception $e) {
            $this->log("❌ Error en vista de estadísticas: " . $e->getMessage());
            $errors++;
        }
        
        if ($errors === 0) {
            $this->log("🎉 MIGRACIÓN COMPLETADA EXITOSAMENTE");
            return true;
        } else {
            $this->log("⚠️ Migración completada con $errors errores");
            return false;
        }
    }
    
    public function generateMigrationReport() {
        $this->log("=== GENERANDO REPORTE DE MIGRACIÓN ===");
        
        $report_file = 'migration_report_' . date('Y-m-d_H-i-s') . '.txt';
        $report_content = implode("\n", $this->log);
        
        file_put_contents($report_file, $report_content);
        $this->log("📄 Reporte guardado en: $report_file");
        
        // Mostrar resumen
        $result = $this->conn->query("SELECT * FROM license_stats LIMIT 1");
        if ($result) {
            $stats = $result->fetch_assoc();
            
            echo "\n" . str_repeat("=", 60) . "\n";
            echo "📊 RESUMEN POST-MIGRACIÓN\n";
            echo str_repeat("=", 60) . "\n";
            echo "Total de licencias: {$stats['total_licenses']}\n";
            echo "Licencias activas: {$stats['active_licenses']}\n";
            echo "Con número de teléfono: {$stats['licenses_with_phone']}\n";
            echo "Limitadas en tiempo: {$stats['time_limited_licenses']}\n";
            echo "Permanentes: {$stats['permanent_licenses']}\n";
            echo "Por expirar (30 días): {$stats['expiring_soon']}\n";
            echo "Total activaciones: {$stats['total_activations']}\n";
            echo str_repeat("=", 60) . "\n";
        }
        
        return $report_file;
    }
    
    public function runFullMigration() {
        echo "\n🔄 INICIANDO MIGRACIÓN COMPLETA A v1.1\n";
        echo str_repeat("=", 60) . "\n\n";
        
        // 1. Verificar versión actual
        $current_version = $this->checkCurrentVersion();
        if ($current_version === '1.1') {
            echo "\n✅ La base de datos ya está actualizada. No es necesario migrar.\n";
            return true;
        }
        
        // 2. Crear respaldo
        if (!$this->backupDatabase()) {
            echo "\n❌ Error creando respaldo. Migración cancelada.\n";
            return false;
        }
        
        // 3. Actualizar esquema
        $this->updateDatabaseSchema();
        
        // 4. Migrar datos
        $this->migrateExistingData();
        
        // 5. Actualizar vistas
        $this->updateViews();
        
        // 6. Validar migración
        $success = $this->validateMigration();
        
        // 7. Generar reporte
        $report_file = $this->generateMigrationReport();
        
        echo "\n" . str_repeat("=", 60) . "\n";
        if ($success) {
            echo "🎉 MIGRACIÓN COMPLETADA EXITOSAMENTE\n";
            echo "📄 Revisa el reporte: $report_file\n";
            echo "💾 Respaldo disponible en tabla 'licenses_backup'\n";
        } else {
            echo "⚠️ MIGRACIÓN COMPLETADA CON ADVERTENCIAS\n";
            echo "📄 Revisa el reporte para más detalles: $report_file\n";
        }
        echo str_repeat("=", 60) . "\n\n";
        
        return $success;
    }
}

// =============================================================================
// EJECUTAR MIGRACIÓN
// =============================================================================

if (php_sapi_name() === 'cli') {
    $migration = new LicenseMigration($db_config);
    $migration->runFullMigration();
} else {
    // Para ejecución web (con precaución)
    if (isset($_GET['confirm']) && $_GET['confirm'] === 'yes_migrate_now') {
        echo "<pre>";
        $migration = new LicenseMigration($db_config);
        $migration->runFullMigration();
        echo "</pre>";
    } else {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Migración Sistema de Licencias v1.1</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
                .btn-danger { background: #dc3545; }
            </style>
        </head>
        <body>
            <h1>🔄 Migración Sistema de Licencias v1.1</h1>
            
            <div class="warning">
                <h3>⚠️ ADVERTENCIA IMPORTANTE</h3>
                <p>Esta migración realizará cambios permanentes en tu base de datos:</p>
                <ul>
                    <li>Agregará campos de teléfono y período a las licencias</li>
                    <li>Creará un respaldo automático de seguridad</li>
                    <li>Migrará datos existentes</li>
                    <li>Actualizará vistas y estadísticas</li>
                </ul>
                <p><strong>Recomendamos ejecutar esto en un entorno de prueba primero.</strong></p>
            </div>
            
            <h3>Pasos a seguir:</h3>
            <ol>
                <li>Asegúrate de tener un respaldo reciente de tu base de datos</li>
                <li>Verifica que no hay usuarios activos en el sistema</li>
                <li>Ejecuta la migración haciendo clic en el botón de abajo</li>
                <li>Revisa el reporte de migración generado</li>
            </ol>
            
            <p>
                <a href="?confirm=yes_migrate_now" class="btn btn-danger" 
                   onclick="return confirm('¿Estás seguro de ejecutar la migración? Esta acción no se puede deshacer.')">
                   🚀 Ejecutar Migración
                </a>
            </p>
            
            <p><small>Tiempo estimado: 1-5 minutos dependiendo del número de licencias.</small></p>
        </body>
        </html>
        <?php
    }
}
?>