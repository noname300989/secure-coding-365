<?php
// File: src/SecurePaymentService.php
// ✅ SECURE: Masked PAN logging — never log full card numbers

use Monolog\Logger;

class SecurePaymentService
{
    public function __construct(
        private readonly Logger $logger,
        private readonly PaymentGateway $gateway
    ) {}

    public function processPayment(string $cardNumber, float $amount, string $currency = 'USD'): PaymentResult
    {
        // ✅ Mask PAN: show only last 4 digits (PCI-DSS requirement)
        $maskedCard = str_repeat('*', strlen($cardNumber) - 4) . substr($cardNumber, -4);

        $this->logger->info('Payment initiated', [
            'card_masked' => $maskedCard,   // '************1234' — never full PAN
            'amount'      => $amount,
            'currency'    => $currency,
            // ❌ Never log: $cardNumber, CVV, expiry date, billing address
        ]);

        try {
            $result = $this->gateway->charge($cardNumber, $amount, $currency);

            $this->logger->info('Payment successful', [
                'card_masked'       => $maskedCard,
                'amount'            => $amount,
                'currency'          => $currency,
                'transaction_id'    => $result->transactionId,
            ]);

            return $result;

        } catch (\RuntimeException $e) {
            // ✅ Log technical details internally for debugging
            $this->logger->error('Payment gateway failure', [
                'card_masked'   => $maskedCard,
                'amount'        => $amount,
                'error'         => $e->getMessage(),
                'code'          => $e->getCode(),
                'gateway'       => get_class($this->gateway),
            ]);

            // ✅ Throw a sanitized exception outward — no internal detail leaks
            throw new \RuntimeException(
                'Payment processing failed. Please try again or contact support.'
            );
        }
    }

    /**
     * Mask API tokens for logging — show only first 8 chars
     * Use for: OAuth tokens, API keys, session IDs
     */
    public static function maskToken(string $token): string
    {
        if (strlen($token) <= 8) {
            return str_repeat('*', strlen($token));
        }
        return substr($token, 0, 8) . '...';
    }
}

// Usage example:
// $logger->info('API call', ['token' => SecurePaymentService::maskToken($apiKey)]);
// Output: 'token' => 'sk_live_...'
