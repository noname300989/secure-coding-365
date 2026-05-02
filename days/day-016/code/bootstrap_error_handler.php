<?php
// File: bootstrap/error_handler.php
// ✅ SECURE: Custom exception + error handler using Monolog
// Run: composer require monolog/monolog

require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\JsonFormatter;
use Monolog\Processor\IntrospectionProcessor;

function buildLogger(): Logger {
    $log = new Logger('app');

    // Rotating file handler: keep 30 days, 10MB max per file
    // This prevents disk exhaustion from high log volume
    $handler = new RotatingFileHandler(
        '/var/log/app/app.log',
        30,
        Logger::DEBUG
    );

    // JSON format → easy to ingest into Splunk/ELK/CloudWatch
    // Also: JSON serialization automatically escapes \n in values,
    //       helping mitigate CWE-117 log injection
    $handler->setFormatter(new JsonFormatter());
    $log->pushHandler($handler);

    // Also log WARNING+ to stderr (captured by systemd/Docker logs)
    $log->pushHandler(new StreamHandler('php://stderr', Logger::WARNING));

    // Automatically adds file/line/class/function to each log entry
    $log->pushProcessor(new IntrospectionProcessor());

    return $log;
}

$logger = buildLogger();

// Bridge PHP errors (warnings, notices) → exceptions
// This means set_exception_handler() catches EVERYTHING uniformly
set_error_handler(function(int $errno, string $errstr, string $file, int $line): bool {
    if (!(error_reporting() & $errno)) {
        return false; // Respect @ suppression operator
    }
    // ErrorException wraps PHP errors as exceptions
    throw new \ErrorException($errstr, 0, $errno, $file, $line);
});

// Global uncaught exception handler
set_exception_handler(function(\Throwable $e) use ($logger): void {
    // ✅ Log FULL technical details internally — never lose diagnostic info
    $logger->critical('Uncaught exception', [
        'exception' => get_class($e),
        'message'   => $e->getMessage(),
        'file'      => $e->getFile(),
        'line'      => $e->getLine(),
        'trace'     => $e->getTraceAsString(),
        'request'   => $_SERVER['REQUEST_URI'] ?? 'cli',
        'method'    => $_SERVER['REQUEST_METHOD'] ?? 'cli',
        'user_agent'=> $_SERVER['HTTP_USER_AGENT'] ?? '',
    ]);

    // ✅ Show NOTHING useful to the user — generic 500 only
    if (php_sapi_name() !== 'cli') {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'error'   => 'An internal error occurred. Please try again later.',
            'code'    => '500',
            // Never echo $e->getMessage() here!
            // Never include file paths, line numbers, or stack traces!
        ]);
    } else {
        // CLI context: safe to print to stdout for developer
        fwrite(STDERR, "[ERROR] " . get_class($e) . ": " . $e->getMessage() . PHP_EOL);
    }

    exit(1);
});

// Shutdown handler — catches fatal errors that don't throw exceptions
register_shutdown_function(function() use ($logger): void {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        $logger->emergency('Fatal error', [
            'message' => $error['message'],
            'file'    => $error['file'],
            'line'    => $error['line'],
        ]);
    }
});

// ✅ php.ini settings to verify at runtime
if (ini_get('display_errors')) {
    // This should never trigger in production
    $logger->alert('display_errors is ON — this is a misconfiguration in production!');
}
