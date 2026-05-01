<?php

declare(strict_types=1);

namespace Semitexa\Auth\Domain\Contract;

interface AuthHandlerInterface
{
    public function handle(object $payload): ?\Semitexa\Core\Auth\AuthResult;
}
