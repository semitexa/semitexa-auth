<?php

declare(strict_types=1);

namespace Semitexa\Auth\Context;

use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Auth\GuestAuthContext;

final class AuthManager implements AuthContextInterface
{
    private static ?self $instance = null;

    private ?AuthenticatableInterface $user = null;
    private ?AuthResult $lastResult = null;

    private function __construct()
    {
    }

    public static function getInstance(): self
    {
        return self::$instance ??= new self();
    }

    public function getUser(): ?AuthenticatableInterface
    {
        return $this->user;
    }

    public function isGuest(): bool
    {
        return $this->user === null;
    }

    public function setUser(?AuthenticatableInterface $user): void
    {
        $this->user = $user;
    }

    public function setAuthResult(AuthResult $result): void
    {
        $this->lastResult = $result;
        
        if ($result->success && $result->user !== null) {
            $this->user = $result->user;
        } else {
            $this->user = null;
        }
    }

    public function getLastResult(): ?AuthResult
    {
        return $this->lastResult;
    }

    public static function get(): ?self
    {
        return self::$instance;
    }

    public static function getOrFail(): self
    {
        return self::$instance ?? self::getInstance();
    }
}
