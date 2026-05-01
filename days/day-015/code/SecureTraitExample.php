<?php
/**
 * Day 15 - Secure Trait Pattern
 *
 * Rules for secure traits:
 * - No public static properties (shared mutable state = session contamination in PHP-FPM)
 * - Use private instance properties (each using class gets its own copy)
 * - Prefer DateTimeImmutable over DateTime (can't be mutated by caller)
 * - Traits provide behaviour only, not shared state
 */

trait HasTimestamps
{
    // ✅ private instance property — each class using this trait gets its OWN copy
    private ?\DateTimeImmutable $createdAt = null;
    private ?\DateTimeImmutable $updatedAt = null;

    public function setCreatedAt(\DateTimeImmutable $dt): void
    {
        if ($this->createdAt !== null) {
            throw new \LogicException('createdAt is immutable once set');
        }
        $this->createdAt = $dt; // DateTimeImmutable — caller can't mutate via reference
    }

    public function touchUpdatedAt(): void
    {
        $this->updatedAt = new \DateTimeImmutable();
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt; // DateTimeImmutable: calling ->modify() returns NEW object
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }
}

// ❌ DANGEROUS pattern (do NOT do this):
trait DangerousRateLimiter
{
    // public static: shared across all instances in long-running PHP-FPM workers!
    // User A's request count bleeds into User B's request — CWE-362 (Race Condition)
    public static int $requestCount = 0;
}

// ✅ SAFE pattern:
trait SafeRateLimiter
{
    // Per-instance state — each object has its own counter
    private int $requestCount = 0;
    private const MAX_REQUESTS = 100;

    public function checkRateLimit(): void
    {
        $this->requestCount++;
        if ($this->requestCount > self::MAX_REQUESTS) {
            throw new \RuntimeException('Rate limit exceeded');
        }
    }

    public function getRequestCount(): int
    {
        return $this->requestCount;
    }
}

class UserService
{
    use HasTimestamps;
    use SafeRateLimiter;

    public function __construct(private readonly string $userId) {}
}

$svc = new UserService('user-42');
$svc->setCreatedAt(new \DateTimeImmutable('2026-01-01'));
$svc->touchUpdatedAt();

echo "Created: " . $svc->getCreatedAt()->format('Y-m-d') . "\n";
