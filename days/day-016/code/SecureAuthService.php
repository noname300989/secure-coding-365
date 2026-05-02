<?php
// File: src/SecureAuthService.php
// ✅ SECURE: Log injection prevention (CWE-117) + proper auth event logging

use Monolog\Logger;

class SecureAuthService
{
    public function __construct(
        private readonly Logger $logger,
        private readonly UserRepository $userRepo
    ) {}

    /**
     * Neutralize log injection by stripping newlines from user input.
     * CWE-117: Improper Output Neutralization for Logs
     *
     * Note: Monolog JsonFormatter JSON-encodes strings so \n becomes \\n,
     * but explicit sanitization is defense-in-depth and good practice
     * when mixing log backends (syslog, raw file, etc.)
     */
    private function sanitizeForLog(string $input): string
    {
        // Remove CR, LF, tab — characters used to inject fake log lines
        $sanitized = preg_replace('/[\r\n\t]/', '_', $input);
        // Also cap length to prevent log flooding via huge inputs
        return mb_substr($sanitized, 0, 255);
    }

    /**
     * Validate and sanitize IP for logging
     */
    private function sanitizeIp(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'invalid_ip';
    }

    public function loginAttempt(string $username, string $password, string $ip): bool
    {
        // ✅ Always sanitize user-controlled strings before logging
        $safeUsername = $this->sanitizeForLog($username);
        $safeIp       = $this->sanitizeIp($ip);

        // ❌ NEVER log the password — not even hashed
        // ❌ NEVER log session IDs (allows session replay)

        $user = $this->userRepo->findByUsername($username);

        if ($user === null) {
            // ✅ Log failed attempt — required for brute-force detection
            $this->logger->warning('Login failed: unknown user', [
                'username'  => $safeUsername,
                'ip'        => $safeIp,
                'reason'    => 'user_not_found',
                'ts'        => date('c'),
            ]);
            // ✅ Same response as wrong password — prevents username enumeration
            return false;
        }

        if (!password_verify($password, $user->passwordHash)) {
            $this->logger->warning('Login failed: wrong password', [
                'username'  => $safeUsername,
                'ip'        => $safeIp,
                'user_id'   => $user->id,
                'reason'    => 'wrong_password',
                'ts'        => date('c'),
            ]);
            return false;
        }

        // ✅ Log successful login
        $this->logger->info('Login successful', [
            'username'  => $safeUsername,
            'ip'        => $safeIp,
            'user_id'   => $user->id,
            'ts'        => date('c'),
            // session ID is NOT logged — it's a secret credential
        ]);

        return true;
    }

    public function adminAction(int $userId, string $action, array $context = []): void
    {
        // ✅ All admin actions must be logged (OWASP A09)
        $this->logger->notice('Admin action performed', [
            'admin_user_id' => $userId,
            'action'        => $this->sanitizeForLog($action),
            'context'       => $context,
            'ts'            => date('c'),
        ]);
    }
}
