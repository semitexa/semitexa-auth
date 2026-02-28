<?php

declare(strict_types=1);

namespace Semitexa\Auth\Context;

use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthResult;
use Swoole\Coroutine;

/**
 * Coroutine-safe storage for auth context.
 *
 * In Swoole HTTP mode each request runs in its own coroutine.
 * Swoole\Coroutine::getContext() returns an ArrayObject that is
 * isolated per-coroutine and automatically destroyed when the
 * coroutine finishes, so there is no state bleed between requests.
 *
 * Outside of a coroutine (CLI, tests) a plain static fallback is used.
 */
final class AuthContextStore
{
    private const USER_KEY   = '__auth_user';
    private const RESULT_KEY = '__auth_result';

    /** Fallback for non-coroutine mode (CLI, tests). */
    private static ?AuthenticatableInterface $fallbackUser = null;
    private static ?AuthResult $fallbackResult = null;

    public static function setUser(?AuthenticatableInterface $user): void
    {
        if (self::inCoroutine()) {
            $ctx = Coroutine::getContext();
            $ctx[self::USER_KEY] = $user;

            return;
        }

        self::$fallbackUser = $user;
    }

    public static function getUser(): ?AuthenticatableInterface
    {
        if (self::inCoroutine()) {
            return Coroutine::getContext()[self::USER_KEY] ?? null;
        }

        return self::$fallbackUser;
    }

    public static function setResult(AuthResult $result): void
    {
        if (self::inCoroutine()) {
            $ctx = Coroutine::getContext();
            $ctx[self::RESULT_KEY] = $result;

            return;
        }

        self::$fallbackResult = $result;
    }

    public static function getResult(): ?AuthResult
    {
        if (self::inCoroutine()) {
            return Coroutine::getContext()[self::RESULT_KEY] ?? null;
        }

        return self::$fallbackResult;
    }

    /**
     * Reset fallback state (useful in CLI/test teardown).
     */
    public static function clearFallback(): void
    {
        self::$fallbackUser   = null;
        self::$fallbackResult = null;
    }

    private static function inCoroutine(): bool
    {
        return class_exists(Coroutine::class, false) && Coroutine::getCid() > 0;
    }
}
