<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/python_bridge.php';

echo "PHP SAPI: " . PHP_SAPI . PHP_EOL;
echo "PHP_BINARY: " . PHP_BINARY . PHP_EOL;
echo "TEMP: " . sys_get_temp_dir() . PHP_EOL;
echo "CA file expected: " . __DIR__ . '/certs/ca.crt' . PHP_EOL;
echo "CA exists: " . (is_file(__DIR__ . '/certs/ca.crt') ? 'YES' : 'NO') . PHP_EOL;
echo "CA readable: " . (is_readable(__DIR__ . '/certs/ca.crt') ? 'YES' : 'NO') . PHP_EOL;
echo "OpenSSL: " . (extension_loaded('openssl') ? 'YES' : 'NO') . PHP_EOL;
echo "hash_hkdf: " . (function_exists('hash_hkdf') ? 'YES' : 'NO') . PHP_EOL;
echo "exec: " . (function_exists('exec') ? 'YES' : 'NO') . PHP_EOL;
echo "popen: " . (function_exists('popen') ? 'YES' : 'NO') . PHP_EOL;

try {
    $started = PythonBridge::start();
    echo "PythonBridge::start(): " . ($started ? 'START REQUESTED' : 'ALREADY RUNNING / RUNTIME FRESH') . PHP_EOL;
    echo "Runtime: " . PythonBridge::runtimePath() . PHP_EOL;
    echo "Log: " . PythonBridge::logPath() . PHP_EOL;
} catch (Throwable $e) {
    echo "START ERROR: " . $e->getMessage() . PHP_EOL;
}
