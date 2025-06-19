<?php
/**
 * Clase para manejar la lógica del sistema de licencias.
 * Reutilizable por el Panel de Administración y la API.
 */

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
            // En un entorno de API, no "die", sino manejar el error de forma controlada
            error_log("Database connection failed: " . $this->conn->connect_error);
            // Para la API, podrías lanzar una excepción o devolver un estado de error
            // Para el panel, die es aceptable, pero lo manejamos de forma global aquí.
            throw new Exception("Error de conexión a la base de datos: " . $this->conn->connect_error);
        }

        $this->conn->set_charset("utf8mb4");
    }

    public function getDbConnection() {
        return $this->conn;
    }

    public function authenticate($username, $password) {
        $stmt = $this->conn->prepare("SELECT id, username, password, role FROM license_admins WHERE username = ? AND status = 1");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password'])) {
                return $user; // Devuelve los datos del usuario si la autenticación es exitosa
            }
        }
        return false;
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

    public function getLicenseDetails($license_id) {
        $stmt = $this->conn->prepare("SELECT * FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }

    public function updateLicense($data) {
        $stmt = $this->conn->prepare("
            UPDATE licenses
            SET client_name = ?, client_email = ?, product_name = ?, version = ?,
                license_type = ?, max_domains = ?, expires_at = ?, notes = ?, status = ?
            WHERE id = ?
        ");

        $expires_at = !empty($data['expires_at']) ? $data['expires_at'] : null;

        $stmt->bind_param("sssssisssi",
            $data['client_name'],
            $data['client_email'],
            $data['product_name'],
            $data['version'],
            $data['license_type'],
            $data['max_domains'],
            $expires_at,
            $data['notes'],
            $data['status'],
            $data['id']
        );

        if ($stmt->execute()) {
            return ['success' => true];
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
        // Opcional: También podrías eliminar las activaciones asociadas
        // $stmt_activations = $this->conn->prepare("DELETE FROM license_activations WHERE license_id = ?");
        // $stmt_activations->bind_param("i", $license_id);
        // $stmt_activations->execute();

        $stmt = $this->conn->prepare("DELETE FROM licenses WHERE id = ?");
        $stmt->bind_param("i", $license_id);
        return $stmt->execute();
    }

    public function getRecentLogs($limit = 50, $action_filter = '', $status_filter = '', $search = '') {
        $where_clauses = [];
        $params = [];
        $types = '';

        if (!empty($action_filter)) {
            $where_clauses[] = "ll.action = ?";
            $params[] = $action_filter;
            $types .= 's';
        }
        if (!empty($status_filter)) {
            $where_clauses[] = "ll.status = ?";
            $params[] = $status_filter;
            $types .= 's';
        }
        if (!empty($search)) {
            $where_clauses[] = "(ll.message LIKE ? OR l.client_name LIKE ? OR l.license_key LIKE ?)";
            $search_param = "%{$search}%";
            $params[] = $search_param;
            $params[] = $search_param;
            $params[] = $search_param;
            $types .= 'sss';
        }

        $where_sql = count($where_clauses) > 0 ? "WHERE " . implode(" AND ", $where_clauses) : "";

        $sql = "
            SELECT ll.*, l.client_name, l.license_key
            FROM license_logs ll
            LEFT JOIN licenses l ON ll.license_id = l.id
            {$where_sql}
            ORDER BY ll.created_at DESC
            LIMIT ?
        ";

        $params[] = $limit;
        $types .= 'i';

        $stmt = $this->conn->prepare($sql);
        if (!empty($params)) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
}
?>