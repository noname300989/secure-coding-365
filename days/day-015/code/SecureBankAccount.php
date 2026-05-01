<?php
/**
 * Day 15 - SECURE: BankAccount with encapsulation, interfaces, and immutability
 *
 * Security properties:
 * - private properties: language-level encapsulation
 * - readonly $owner: immutable once set
 * - final class: no override attacks
 * - Constructor validation: invalid state cannot be constructed
 * - Auditable interface: enforced audit log contract
 */

require_once __DIR__ . '/Money.php';

interface Auditable
{
    public function getAuditLog(): array;
}

final class BankAccount implements Auditable
{
    private Money $balance;           // private: only THIS class can touch balance
    private bool $isFrozen = false;   // private: callers cannot bypass freeze
    private array $auditLog = [];
    private readonly string $owner;   // readonly: set once, never changed

    public function __construct(string $owner, Money $initialBalance)
    {
        if (trim($owner) === '') {
            throw new \InvalidArgumentException('Owner name cannot be empty');
        }
        $this->owner   = $owner;
        $this->balance = $initialBalance;
        $this->log('ACCOUNT_CREATED', $initialBalance->amountCents);
    }

    /** Read-only getter — caller gets a copy of immutable Money object */
    public function getBalance(): Money
    {
        return $this->balance;
    }

    public function getOwner(): string
    {
        return $this->owner;
    }

    public function freeze(): void
    {
        $this->isFrozen = true;
        $this->log('ACCOUNT_FROZEN', 0);
    }

    public function withdraw(Money $amount): void
    {
        if ($this->isFrozen) {
            throw new \RuntimeException('Account is frozen — withdrawal denied');
        }
        // Money::subtract() throws UnderflowException on insufficient funds
        // Money constructor enforces non-negative, preventing negative withdrawals
        $this->balance = $this->balance->subtract($amount);
        $this->log('WITHDRAWAL', $amount->amountCents);
    }

    public function deposit(Money $amount): void
    {
        if ($this->isFrozen) {
            throw new \RuntimeException('Account is frozen — deposit denied');
        }
        $this->balance = $this->balance->add($amount);
        $this->log('DEPOSIT', $amount->amountCents);
    }

    /** Implements Auditable interface */
    public function getAuditLog(): array
    {
        return $this->auditLog;
    }

    private function log(string $event, int $cents): void
    {
        $this->auditLog[] = [
            'event'     => $event,
            'amount'    => $cents,
            'timestamp' => time(),
        ];
    }
}

// --- Safe usage ---
$initialBalance = new Money(10000, 'USD'); // $100.00
$account = new BankAccount('Alice', $initialBalance);

$account->withdraw(new Money(500, 'USD')); // $5.00
$account->deposit(new Money(2000, 'USD')); // $20.00

echo "Balance: " . $account->getBalance() . "\n"; // USD 115.00
echo "Owner:   " . $account->getOwner()   . "\n"; // Alice
echo "Log:     " . count($account->getAuditLog()) . " entries\n";

// These ALL fail at the language level (try them!):
// $account->owner   = 'Attacker'; // Error: Cannot modify readonly property
// $account->balance = new Money(999999, 'USD'); // Error: private property
// $account->isFrozen = false;     // Error: private property
