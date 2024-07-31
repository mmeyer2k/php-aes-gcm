<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use Exception;
use Throwable;

class AesGcmException extends Exception
{
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        $message = $message ?: openssl_error_string() ?: 'An OpenSSL error occurred';

        parent::__construct($message, $code, $previous);
    }
}
