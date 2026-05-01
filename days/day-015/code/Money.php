<?php
/**
 * Day 15 - SECURE: Immutable Money Value Object
 *
 * - readonly properties: set once in constructor, never changed
 * - Constructor validation: invalid Money cannot exist
 * - Immutable operations: add/subtract return NEW objects
 * - Integer cents: avoids float rounding errors (CWE-681)
 */

final class Money
{
    public function __construct(
        public readonly int $amountCents, // Store cents (int), never floats for money!
        public readonly string $currency,
    ) {
        if ($amountCents < 0) {
            throw new \InvalidArgumentException(
                'Money amount cannot be negative: ' . $amountCents
            );
        }
        if (!in_array($currency, ['USD', 'EUR', 'GBP', 'INR'], true)) {
            throw new \InvalidArgumentException('Unsupported currency: ' . $currency);
        }
    }

    /** Returns a NEW Money object — original is unchanged (immutability) */
    public function add(Money $other): self
    {
        if ($this->currency !== $other->currency) {
            throw new \LogicException('Cannot add different currencies');
        }
        return new self($this->amountCents + $other->amountCents, $this->currency);
    }

    /** Returns a NEW Money object — throws if result would be negative */
    public function subtract(Money $other): self
    {
        if ($this->currency !== $other->currency) {
            throw new \LogicException('Cannot subtract different currencies');
        }
        $result = $this->amountCents - $other->amountCents;
        if ($result < 0) {
            throw new \UnderflowException('Insufficient funds');
        }
        return new self($result, $this->currency);
    }

    public function equals(Money $other): bool
    {
        return $this->amountCents === $other->amountCents
            && $this->currency === $other->currency;
    }

    public function __toString(): string
    {
        return sprintf('%s %.2f', $this->currency, $this->amountCents / 100);
    }
}
