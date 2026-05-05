<?php

declare(strict_types=1);

namespace Semitexa\Auth\Context;

use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Lifecycle\PerRequestStateRegistry;
use Swoole\Coroutine;

/**
 * Coroutine-safe storage for auth context.
 *
 * In Swoole HTTP mode each request runs in its own coroutine.
 * Swoole\Coroutine::getContext() returns an ArrayObject that is
 * isolated per-coroutine and automatically destroyed when the
 * coroutine finishes, so there is no state bleed between requests.
 *
 * Outside of a coroutine (CLI / queue worker / tests) the static fallback
 * fields below would survive across requests if nothing reset them. The
 * store self-registers clear() with PerRequestStateRegistry so the framework
 * wipes the fallback in the finally block of every Application::handleRequest
 * and QueueWorker::processPayload — same lifecycle hook RbacDecisionCache
 * and CurrentRequestStore use.
 */
final class AuthContextStore
{
    private const USER_KEY   = '__auth_user';
    private const RESULT_KEY = '__auth_result';
    private const REGISTRY_NAME = 'auth_context_store';

    /** Fallback for non-coroutine mode (CLI, tests). */
    private static ?AuthenticatableInterface $fallbackUser = null;
    private static ?AuthResult $fallbackResult = null;

    private static bool $registered = false;

    public static function setUser(?AuthenticatableInterface $user): void
    {
        self::ensureRegistered();
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
        self::ensureRegistered();
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

    public static function clear(): void
    {
        if (self::inCoroutine()) {
            $ctx = Coroutine::getContext();
            unset($ctx[self::USER_KEY], $ctx[self::RESULT_KEY]);

            return;
        }

        self::$fallbackUser = null;
        self::$fallbackResult = null;
    }

    /**
     * Reset fallback state (useful in CLI/test teardown).
     */
    public static function clearFallback(): void
    {
        self::$fallbackUser = null;
        self::$fallbackResult = null;
    }

    private static function inCoroutine(): bool
    {
        return class_exists(Coroutine::class, false) && Coroutine::getCid() > 0;
    }

    /**
     * Lazy registration: the first set*() call wires clear() into the
     * framework's per-request lifecycle. Idempotent — re-registration is a
     * no-op so concurrent first-touches in separate coroutines are safe.
     */
    private static function ensureRegistered(): void
    {
        if (self::$registered) {
            return;
        }
        self::$registered = true;
        PerRequestStateRegistry::register(
            self::REGISTRY_NAME,
            static function (): void {
                self::clear();
                self::clearFallback();
            },
        );
    }
}
