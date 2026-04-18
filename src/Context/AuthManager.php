<?php

declare(strict_types=1);

namespace Semitexa\Auth\Context;

use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthResult;

/**
 * Request-scoped auth context backed by AuthContextStore.
 *
 * AuthContextStore isolates state per Swoole coroutine, so concurrent
 * HTTP requests never share auth data regardless of how many times
 * getInstance() is called within the same process.
 *
 * Registered as the AuthContextInterface binding so Core-owned consumers
 * (SessionPhase, ErrorRouteDispatcher, AuthBootstrapperFactory, etc.) resolve
 * this implementation via DI rather than importing the concrete class.
 */
#[SatisfiesServiceContract(of: AuthContextInterface::class)]
class AuthManager implements AuthContextInterface
{
    /** @deprecated Use DI to obtain AuthContextInterface instead. Will be removed in next major version. */
    private static ?self $instance = null;

    public function __construct()
    {
    }

    /**
     * @deprecated Use DI to obtain AuthContextInterface instead.
     */
    public static function getInstance(): self
    {
        return self::$instance ??= new self();
    }

    public function getUser(): ?AuthenticatableInterface
    {
        return AuthContextStore::getUser();
    }

    public function isGuest(): bool
    {
        return AuthContextStore::getUser() === null;
    }

    public function setUser(?AuthenticatableInterface $user): void
    {
        AuthContextStore::setUser($user);
    }

    public function resetToGuest(): void
    {
        AuthContextStore::clear();
    }

    public function setAuthResult(AuthResult $result): void
    {
        AuthContextStore::setResult($result);

        if ($result->success && $result->user !== null) {
            AuthContextStore::setUser($result->user);
        } else {
            AuthContextStore::setUser(null);
        }
    }

    public function getLastResult(): ?AuthResult
    {
        return AuthContextStore::getResult();
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
