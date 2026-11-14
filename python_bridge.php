<?php
/**
 * Persistent PHP client for the supplied Python TLS/AES-GCM server.
 * PHP 7.4+, OpenSSL, hash_hkdf().
 */
class PythonBridge
{
    // ---------------- CONFIGURATION ----------------
    private const HOST = '141.11.190.106'; // Use server IP/DNS if remote
    private const PORT = 43979;        // server(3).py listens on 7091
    private const CA_CERT_FILE = __DIR__ . '/certs/ca.crt';
    private const PRE_SHARED_KEY = '7mQx9VbK2pLwF4nYc8TjH6sRzA1eU5dG';
    private const RECONNECT_DELAY = 10;
    private const HEARTBEAT_INTERVAL = 10;
    private const HEARTBEAT_TIMEOUT = 35;
    private const ACK_RETRY_INTERVAL = 10;
    private const MAX_FRAME_SIZE = 8 * 1024 * 1024;
    // ------------------------------------------------

    private static function dir(): string { return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'python_bridge'; }
    private static function queueDir(): string { return self::dir() . DIRECTORY_SEPARATOR . 'outgoing'; }
    private static function runtimeFile(?string $date = null): string
    {
        return self::dir() . DIRECTORY_SEPARATOR . 'runtime_' . ($date ?? date('Y-m-d')) . '.json';
    }
    private static function log(string $text): void
    {
        if (!is_dir(self::dir())) @mkdir(self::dir(), 0700, true);
        @file_put_contents(self::dir() . DIRECTORY_SEPARATOR . 'python_bridge.log',
            '[' . date('Y-m-d H:i:s') . '] ' . $text . PHP_EOL, FILE_APPEND);
    }
    private static function ensureDirs(): void
    {
        foreach ([self::dir(), self::queueDir()] as $d) {
            if (!is_dir($d) && !@mkdir($d, 0700, true) && !is_dir($d)) {
                throw new RuntimeException('Cannot create directory: ' . $d);
            }
        }
    }

    /** Best-effort daily runtime guard. Intentionally no flock, per request. */
    public static function start(): bool
    {
        self::ensureDirs();
        if (!is_file(self::CA_CERT_FILE)) throw new RuntimeException('CA certificate missing: ' . self::CA_CERT_FILE);
        if (self::PRE_SHARED_KEY === '' || self::PRE_SHARED_KEY === 'PASTE_THE_EXACT_SAME_PSK_AS_SERVER_PY') {
            throw new RuntimeException('Set PRE_SHARED_KEY in python_bridge.php first.');
        }
        $runtime = self::runtimeFile();
        // Worker refreshes runtime mtime every loop. Old file means stale worker marker.
        if (is_file($runtime) && (time() - filemtime($runtime) < 40)) return false;
        if (is_file($runtime)) @unlink($runtime);
        @file_put_contents($runtime, json_encode(['pid' => null, 'date' => date('Y-m-d'), 'started_at' => date(DATE_ATOM)]));

        $php = self::findPhpCli();
        $script = __FILE__;
        $log = self::dir() . DIRECTORY_SEPARATOR . 'python_bridge.log';
        if (PHP_OS_FAMILY === 'Windows') {
            if (!function_exists('popen')) { @unlink($runtime); throw new RuntimeException('popen() is disabled.'); }
            $cmd = 'start /B "" ' . escapeshellarg($php) . ' ' . escapeshellarg($script)
                . ' --worker >> ' . escapeshellarg($log) . ' 2>&1';
            $p = @popen($cmd, 'r');
            if (!is_resource($p)) { @unlink($runtime); throw new RuntimeException('Cannot start background worker.'); }
            pclose($p);
        } else {
            if (!function_exists('exec')) { @unlink($runtime); throw new RuntimeException('exec() is disabled; cannot start worker.'); }
            $cmd = 'nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($script)
                . ' --worker >> ' . escapeshellarg($log) . ' 2>&1 < /dev/null &';
            exec($cmd, $out, $status);
            if ($status !== 0) { @unlink($runtime); throw new RuntimeException('Background worker launch failed.'); }
        }
        self::log('Worker launch requested.');
        return true;
    }

    private static function findPhpCli(): string
    {
        $candidates = [];
        if (defined('PHP_BINDIR')) $candidates[] = PHP_BINDIR . DIRECTORY_SEPARATOR . (PHP_OS_FAMILY === 'Windows' ? 'php.exe' : 'php');
        $candidates[] = PHP_BINARY;
        foreach ($candidates as $p) if (is_file($p) && is_executable($p)) return $p;
        return PHP_BINARY;
    }

    /** Queue client-to-server text; worker sends/retries it until Python ACKs. */
    public static function sendText(string $text): string
    {
        self::ensureDirs();
        self::start();
        $id = self::uuid();
        $data = json_encode(['id' => $id, 'text' => $text, 'created_at' => date(DATE_ATOM)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($data === false) throw new RuntimeException('Cannot encode outgoing message.');
        $file = self::queueDir() . DIRECTORY_SEPARATOR . $id . '.json';
        $tmp = $file . '.tmp';
        if (@file_put_contents($tmp, $data, LOCK_EX) === false || !@rename($tmp, $file)) {
            @unlink($tmp); throw new RuntimeException('Cannot write message queue.');
        }
        return $id;
    }

    public static function runtimePath(): string { return self::runtimeFile(); }
    public static function logPath(): string { return self::dir() . DIRECTORY_SEPARATOR . 'python_bridge.log'; }

    private static function uuid(): string
    {
        $b = random_bytes(16); $b[6] = chr((ord($b[6]) & 0x0f) | 0x40); $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        $h = bin2hex($b);
        return substr($h,0,8).'-'.substr($h,8,4).'-'.substr($h,12,4).'-'.substr($h,16,4).'-'.substr($h,20,12);
    }
    private static function key(): string
    {
        return hash_hkdf('sha256', self::PRE_SHARED_KEY, 32, 'application-aes-256-gcm', 'client-server-protocol-v1');
    }
    private static function lrc(string $s): int
    {
        $v = 0; for ($i=0, $n=strlen($s); $i<$n; $i++) $v ^= ord($s[$i]); return $v;
    }
    private static function seal(array $msg): string
    {
        $plain = json_encode($msg, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($plain === false) throw new RuntimeException('JSON encode failed.');
        $nonce = random_bytes(12); $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
        if ($cipher === false) throw new RuntimeException('AES-GCM encryption failed.');
        $env = json_encode(['nonce'=>base64_encode($nonce), 'ciphertext'=>base64_encode($cipher.$tag)]);
        if ($env === false || strlen($env) > self::MAX_FRAME_SIZE) throw new RuntimeException('Frame too large.');
        return pack('N', strlen($env)) . $env;
    }
    private static function openSealed(string $env): array
    {
        $e = json_decode($env, true, 512, JSON_THROW_ON_ERROR);
        $nonce = base64_decode($e['nonce'] ?? '', true); $combined = base64_decode($e['ciphertext'] ?? '', true);
        if ($nonce === false || strlen($nonce)!==12 || $combined===false || strlen($combined)<16) throw new RuntimeException('Invalid envelope.');
        $tag = substr($combined,-16); $cipher = substr($combined,0,-16);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $nonce, $tag, '');
        if ($plain === false) throw new RuntimeException('AES-GCM authentication failed.');
        $msg = json_decode($plain, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($msg)) throw new RuntimeException('Invalid message JSON.');
        return $msg;
    }
    private static function writeAll($s, string $data): void
    {
        for ($off=0, $len=strlen($data); $off<$len;) {
            $n = @fwrite($s, substr($data,$off));
            if ($n === false || $n === 0) throw new RuntimeException('Socket write failed.');
            $off += $n;
        }
    }
    private static function readExact($s, int $len): string
    {
        $out='';
        while (strlen($out)<$len) {
            $part=@fread($s,$len-strlen($out));
            if ($part===false || $part==='') {
                $meta=stream_get_meta_data($s);
                if (!empty($meta['timed_out'])) throw new RuntimeException('Socket read timeout.');
                throw new RuntimeException('Python closed the connection.');
            }
            $out.=$part;
        }
        return $out;
    }
    private static function receive($s): array
    {
        $size=unpack('Nsize',self::readExact($s,4))['size'];
        if ($size<=0 || $size>self::MAX_FRAME_SIZE) throw new RuntimeException('Invalid frame size.');
        return self::openSealed(self::readExact($s,$size));
    }
    private static function send($s, array $msg): void { self::writeAll($s,self::seal($msg)); }
    private static function connect()
    {
        if (!is_file(self::CA_CERT_FILE)) throw new RuntimeException('CA certificate missing: '.self::CA_CERT_FILE);
        $ctx=stream_context_create(['ssl'=>[
            'verify_peer'=>true, 'verify_peer_name'=>true,
            'cafile'=>self::CA_CERT_FILE, 'peer_name'=>self::HOST, 'SNI_enabled'=>true,
        ]]);
        $s=@stream_socket_client('tls://'.self::HOST.':'.self::PORT,$errno,$errstr,10,STREAM_CLIENT_CONNECT,$ctx);
        if (!$s) throw new RuntimeException("Connect failed ($errno): $errstr");
        stream_set_timeout($s,40);
        return $s;
    }

    // Customize this method to handle messages initiated from Python's console.
    private static function handleServerMessage(string $text): string
    {
        self::log('Message from Python: '.$text);
        return 'Pesan diterima oleh PHP client';
    }
    private static function processIncoming($s, array $m): void
    {
        $type=$m['type']??'';
        if ($type==='PING') { self::send($s,['type'=>'PONG','id'=>$m['id']??null]); return; }
        if ($type==='PONG') return;
        if ($type==='MESSAGE') {
            $id=(string)($m['id']??''); $text=$m['text']??'';
            if ($id==='' || !is_string($text) || !isset($m['lrc']) || self::lrc($text)!==$m['lrc']) {
                self::send($s,['type'=>'NACK','id'=>$id,'reason'=>'LRC mismatch']); return;
            }
            $reply=self::handleServerMessage($text);
            self::send($s,['type'=>'RESPONSE','id'=>$id,'text'=>$reply,'lrc'=>self::lrc($reply)]);
            return;
        }
        if ($type==='CLIENT_TEXT_ACK') {
            $id=(string)($m['id']??''); if ($id!=='') @unlink(self::queueDir().DIRECTORY_SEPARATOR.$id.'.json');
            self::log('Client message ACK: '.$id); return;
        }
        if ($type==='CLIENT_TEXT_NACK') { self::log('Client message NACK: '.(string)($m['id']??'')); return; }
        self::log('Unknown incoming type: '.$type);
    }
    private static function loadQueue(): array
    {
        $items=[];
        foreach (glob(self::queueDir().DIRECTORY_SEPARATOR.'*.json')?:[] as $f) {
            $raw=@file_get_contents($f); if ($raw===false) continue;
            $v=json_decode($raw,true);
            if (is_array($v) && isset($v['id'],$v['text'])) $items[$v['id']]=['path'=>$f,'text'=>(string)$v['text']];
        }
        return $items;
    }

    public static function worker(): void
    {
        self::ensureDirs();
        $date=date('Y-m-d'); $runtime=self::runtimeFile($date);
        register_shutdown_function(static function() use ($runtime) { @unlink($runtime); });
        @file_put_contents($runtime,json_encode(['pid'=>getmypid(),'date'=>$date,'started_at'=>date(DATE_ATOM)]));
        self::log('Worker started for '.self::HOST.':'.self::PORT);
        $socket=null; $lastRx=0.0; $lastPing=0.0; $lastSent=[];

        while (date('Y-m-d')===$date) {
            try {
                if (!is_resource($socket)) {
                    self::log('Connecting...'); $socket=self::connect();
                    $lastRx=microtime(true); $lastPing=0.0; $lastSent=[];
                    self::log('TLS connected.');
                }
                @touch($runtime);

                // Outgoing Laravel messages: CLIENT_TEXT; retain same ID until ACK.
                foreach (self::loadQueue() as $id=>$item) {
                    if (!isset($lastSent[$id]) || microtime(true)-$lastSent[$id]>=self::ACK_RETRY_INTERVAL) {
                        self::send($socket,['type'=>'CLIENT_TEXT','id'=>$id,'text'=>$item['text'],'lrc'=>self::lrc($item['text'])]);
                        $lastSent[$id]=microtime(true);
                    }
                }

                $now=microtime(true);
                if ($now-$lastPing>=self::HEARTBEAT_INTERVAL) {
                    self::send($socket,['type'=>'PING','id'=>self::uuid()]); $lastPing=$now;
                }
                if ($now-$lastRx>self::HEARTBEAT_TIMEOUT) throw new RuntimeException('Heartbeat timeout.');

                $read=[$socket]; $write=null; $except=null;
                $ready=@stream_select($read,$write,$except,1);
                if ($ready===false) throw new RuntimeException('stream_select failed.');
                if ($ready>0) { self::processIncoming($socket,self::receive($socket)); $lastRx=microtime(true); }
            } catch (Throwable $e) {
                self::log('Connection error: '.$e->getMessage());
                if (is_resource($socket)) @fclose($socket);
                $socket=null; $lastSent=[]; sleep(self::RECONNECT_DELAY);
            }
        }
        if (is_resource($socket)) @fclose($socket);
        self::log('Worker stopped at date change.');
    }
}

if (PHP_SAPI==='cli' && ($argv[1]??'')==='--worker') {
    PythonBridge::worker();
}
