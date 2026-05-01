<?php
/**
 * Day 15 - Mini Challenge Starter: EmailAddress Value Object
 *
 * Complete the implementation following the secure design principles from today's lesson.
 * Requirements:
 * 1. Constructor validates with filter_var(FILTER_VALIDATE_EMAIL)
 * 2. Normalize to lowercase
 * 3. Expose via getValue(): string getter only
 * 4. equals(EmailAddress $other): bool comparison
 * 5. Make class final, property readonly
 * 6. Bonus: getDomain(): string
 */

final class EmailAddress
{
    public readonly string $value;

    public function __construct(string $email)
    {
        $normalized = strtolower(trim($email));

        // TODO: Validate using filter_var with FILTER_VALIDATE_EMAIL
        // Throw \InvalidArgumentException if invalid
        // Hint: filter_var returns false (not null) on failure — check === false

        $this->value = $normalized;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    // TODO: Implement equals()
    // Two EmailAddress objects are equal if their $value is identical

    // TODO (Bonus): Implement getDomain()
    // Return the part after '@' — e.g. 'example.com' from 'alice@example.com'
}

// --- Test your implementation ---
try {
    $email1 = new EmailAddress('Alice@Example.COM');
    $email2 = new EmailAddress('alice@example.com');
    echo "Email:  " . $email1->getValue() . "\n"; // alice@example.com
    // echo "Equal:  " . ($email1->equals($email2) ? 'yes' : 'no') . "\n"; // yes
    // echo "Domain: " . $email1->getDomain() . "\n"; // example.com

    $bad = new EmailAddress('not-an-email'); // Should throw!
    echo "ERROR: Should have thrown!\n";
} catch (\InvalidArgumentException $e) {
    echo "Correctly rejected: " . $e->getMessage() . "\n";
}
