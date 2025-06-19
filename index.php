<?php
/**
 * Página principal del Servidor de Licencias
 * Redirige automáticamente al panel de administración
 */

// Verificar si se está accediendo a la API
$request_uri = $_SERVER['REQUEST_URI'] ?? '';
$query_string = $_SERVER['QUERY_STRING'] ?? '';

// Si hay parámetros de API, redirigir a api.php
if (strpos($query_string, 'action=') !== false || 
    strpos($request_uri, '/api') !== false) {
    require_once 'api.php';
    exit;
}

// Para cualquier otra solicitud, mostrar la página de bienvenida/redirección
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Servidor de Licencias - Sistema de Códigos</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .welcome-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
        }
        
        .feature-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            margin: 0 auto 1rem;
        }
        
        .status-indicator {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .loading-spinner {
            display: none;
        }
        
        .btn-gradient {
            background: linear-gradient(135deg, #667eea, #764ba2);
            border: none;
            color: white;
        }
        
        .btn-gradient:hover {
            background: linear-gradient(135deg, #5a67d8, #6b46c1);
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        }
    </style>
</head>
<body>
    <div class="container-fluid d-flex align-items-center justify-content-center min-vh-100 py-4">
        <div class="welcome-card p-5" style="max-width: 800px; width: 100%;">
            
            <!-- Header -->
            <div class="text-center mb-5">
                <div class="mb-3">
                    <i class="fas fa-shield-alt fa-4x text-primary"></i>
                </div>
                <h1 class="display-5 fw-bold text-dark mb-3">Servidor de Licencias</h1>
                <p class="lead text-muted">Sistema de Códigos - Gestión y Validación de Licencias</p>
                
                <!-- Status indicator -->
                <div class="d-flex justify-content-center align-items-center mt-3">
                    <span class="badge bg-success status-indicator me-2">
                        <i class="fas fa-circle"></i> ONLINE
                    </span>
                    <small class="text-muted">Servidor activo y funcionando</small>
                </div>
            </div>
            
            <!-- Features -->
            <div class="row mb-5">
                <div class="col-md-4 text-center mb-4">
                    <div class="feature-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    <h5>Generación de Licencias</h5>
                    <p class="text-muted small">Crea y gestiona licencias únicas de forma automática</p>
                </div>
                
                <div class="col-md-4 text-center mb-4">
                    <div class="feature-icon">
                        <i class="fas fa-shield-check"></i>
                    </div>
                    <h5>Validación Segura</h5>
                    <p class="text-muted small">Verifica la autenticidad de las licencias en tiempo real</p>
                </div>
                
                <div class="col-md-4 text-center mb-4">
                    <div class="feature-icon">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <h5>Panel de Control</h5>
                    <p class="text-muted small">Administra todas las licencias desde un panel intuitivo</p>
                </div>
            </div>
            
            <!-- Actions -->
            <div class="text-center">
                <h4 class="mb-4">¿Qué deseas hacer?</h4>
                
                <div class="d-grid gap-3 d-md-block">
                    <a href="Psnel_administracion.php" class="btn btn-gradient btn-lg px-4 me-md-3">
                        <i class="fas fa-cog me-2"></i>
                        Panel de Administración
                    </a>
                    
                    <button class="btn btn-outline-primary btn-lg px-4 me-md-3" onclick="checkApiStatus()">
                        <i class="fas fa-heartbeat me-2"></i>
                        <span class="button-text">Verificar API</span>
                        <span class="loading-spinner">
                            <i class="fas fa-spinner fa-spin"></i>
                        </span>
                    </button>
                    
                    <a href="generador_masivo_de_licencias.php" class="btn btn-outline-success btn-lg px-4">
                        <i class="fas fa-magic me-2"></i>
                        Generador Masivo
                    </a>
                </div>
            </div>
            
            <!-- API Status -->
            <div id="apiStatus" class="mt-4" style="display: none;">
                <div class="alert alert-info">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <strong>Estado de la API:</strong>
                            <span id="apiStatusText">Verificando...</span>
                        </div>
                        <div>
                            <strong>Versión:</strong>
                            <span id="apiVersion">-</span>
                        </div>
                    </div>
                    <div class="mt-2">
                        <small><strong>Última verificación:</strong> <span id="lastCheck">-</span></small>
                    </div>
                </div>
            </div>
            
            <!-- Footer info -->
            <div class="text-center mt-5 pt-4 border-top">
                <div class="row">
                    <div class="col-md-6">
                        <small class="text-muted">
                            <i class="fas fa-server me-1"></i>
                            Servidor: <?= $_SERVER['SERVER_NAME'] ?? 'localhost' ?>
                        </small>
                    </div>
                    <div class="col-md-6">
                        <small class="text-muted">
                            <i class="fas fa-clock me-1"></i>
                            <?= date('d/m/Y H:i:s') ?> UTC
                        </small>
                    </div>
                </div>
                
                <div class="mt-3">
                    <small class="text-muted">
                        Sistema de Licencias v1.0 - Desarrollado para gestión profesional de licencias de software
                    </small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-redirect después de 10 segundos si no hay interacción
        let autoRedirectTimer;
        
        function startAutoRedirect() {
            autoRedirectTimer = setTimeout(() => {
                window.location.href = 'Psnel_administracion.php';
            }, 10000);
        }
        
        function cancelAutoRedirect() {
            if (autoRedirectTimer) {
                clearTimeout(autoRedirectTimer);
            }
        }
        
        // Verificar estado de la API
        async function checkApiStatus() {
            const button = event.target.closest('button');
            const buttonText = button.querySelector('.button-text');
            const spinner = button.querySelector('.loading-spinner');
            const statusDiv = document.getElementById('apiStatus');
            
            // Mostrar loading
            buttonText.style.display = 'none';
            spinner.style.display = 'inline';
            button.disabled = true;
            
            try {
                const response = await fetch('api.php?action=status');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('apiStatusText').innerHTML = 
                        '<span class="text-success"><i class="fas fa-check-circle me-1"></i>Funcionando correctamente</span>';
                    document.getElementById('apiVersion').textContent = data.data.api_version;
                } else {
                    document.getElementById('apiStatusText').innerHTML = 
                        '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Respuesta inválida</span>';
                }
            } catch (error) {
                document.getElementById('apiStatusText').innerHTML = 
                    '<span class="text-danger"><i class="fas fa-times-circle me-1"></i>Error de conexión</span>';
                document.getElementById('apiVersion').textContent = 'No disponible';
            }
            
            document.getElementById('lastCheck').textContent = new Date().toLocaleString('es-ES');
            statusDiv.style.display = 'block';
            
            // Restaurar botón
            buttonText.style.display = 'inline';
            spinner.style.display = 'none';
            button.disabled = false;
        }
        
        // Event listeners
        document.addEventListener('DOMContentLoaded', function() {
            // Iniciar auto-redirect
            startAutoRedirect();
            
            // Cancelar auto-redirect en cualquier interacción
            document.addEventListener('click', cancelAutoRedirect);
            document.addEventListener('keypress', cancelAutoRedirect);
            document.addEventListener('scroll', cancelAutoRedirect);
            
            // Mensaje de auto-redirect
            setTimeout(() => {
                const toast = document.createElement('div');
                toast.className = 'position-fixed bottom-0 end-0 p-3';
                toast.style.zIndex = '9999';
                toast.innerHTML = `
                    <div class="toast show" role="alert">
                        <div class="toast-header">
                            <i class="fas fa-info-circle text-info me-2"></i>
                            <strong class="me-auto">Auto-redirección</strong>
                            <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                        </div>
                        <div class="toast-body">
                            Serás redirigido al panel de administración en 10 segundos
                        </div>
                    </div>
                `;
                document.body.appendChild(toast);
                
                // Auto-remover el toast
                setTimeout(() => {
                    if (document.body.contains(toast)) {
                        document.body.removeChild(toast);
                    }
                }, 8000);
            }, 2000);
        });
        
        // Verificar API al cargar si es necesario
        window.addEventListener('load', function() {
            // Verificar automáticamente el estado de la API después de 3 segundos
            setTimeout(() => {
                if (document.getElementById('apiStatus').style.display === 'none') {
                    // Solo verificar si el usuario no ha hecho click manualmente
                    checkApiStatus.call({ target: document.querySelector('button[onclick="checkApiStatus()"]') });
                }
            }, 3000);
        });
    </script>
</body>
</html>