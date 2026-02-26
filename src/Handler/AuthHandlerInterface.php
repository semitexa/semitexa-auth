<?php

declare(strict_types=1);

namespace Semitexa\Auth\Handler;

use Semitexa\Core\Contract\PayloadInterface;

interface AuthHandlerInterface
{
    public function handle(PayloadInterface $payload): ?\Semitexa\Core\Auth\AuthResult;
}
