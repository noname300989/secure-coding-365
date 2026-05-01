<?php
/**
 * Day 15 - VULNERABLE: OOP in PHP — Insecure Design
 *
 * Problems:
 * - public properties (CWE-1061: Insufficient Encapsulation)
 * - No constructor validation (invalid state is representable)
 * - No withdrawal validation (negative amounts = free money)
 * - isFrozen bypass (caller can disable freeze directly)
 */

class BankAccount
{
    public string $owner;       // ❌ Anyone can change the owner!
    public float $balance;      // ❌ Directly writable - no audit trail
    public string $accountType; // ❌ No validation - 'superadmin' is allowed
    public bool $isFrozen;      // ❌ Caller can unfreeze at will

    public function __construct(string $owner, float $balance)
    {
        $this->owner    = $owner;
        $this->balance  = $balance; // ❌ Negative balance allowed
        $this->isFrozen = false;
    }

    public function withdraw(float $amount): void
    {
        // ❌ CWE-20: No validation — negative $amount = deposit!
        $this->balance -= $amount;
    }
}

// --- Attacker code (or careless developer) ---
$account = new BankAccount('Alice', 100.0);

// Ownership hijack
$account->owner = 'Attacker';

// Balance manipulation
$account->balance = 999999.0;

// Bypass account freeze
$account->isFrozen = false;

// Negative withdrawal = deposit
$account->withdraw(-500.0);

echo "Balance: " . $account->balance . "\n"; // 1000499 — money from thin air!
echo "Owner:   " . $account->owner   . "\n"; // Attacker
