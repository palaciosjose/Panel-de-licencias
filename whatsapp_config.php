<?php
// =====================================================================
// ARCHIVO 1: whatsapp_config.php
// =====================================================================

$whatsapp_config = [
    'enabled' => true,
    'token' => 'pvuCPCdQ68NmT2kRBuBvUDvhvSHuFk',
    'endpoint' => 'https://apiwhaticket.streamdigi.co/api/messages/send',
    'timeout' => 30,
    'retry_attempts' => 3,
    'test_mode' => false,
    
    // Configuraciones específicas de Whaticket
    'userId' => '', // ID del usuario o vacío
    'queueId' => '', // ID de la fila o vacío  
    'sendSignature' => false, // Firmar mensajes
    'closeTicket' => false, // Cerrar ticket automáticamente
    
    // Configuraciones de notificaciones
    'expiry_alert_days' => 3, // Días antes de vencer
    'daily_check_hour' => '09:00', // Hora de verificación
    'company_name' => 'Sistema de Códigos',
    'support_phone' => '+573232405812' // Tu número de soporte
];