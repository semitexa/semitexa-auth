<?php

declare(strict_types=1);

namespace Semitexa\Auth\Context;

use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Lifecycle\CarriedContext;
use Semitexa\Core\Lifecycle\PerRequestStateRegistry;
use Semitexa\Core\Support\CoroutineLocal;

/**
 * The signed-in user and auth result of the running request.
 *
 * Kept in {@see CoroutineLocal}: per coroutine in Swoole, a process-local
 * store outside one (CLI, a queue worker, tests). Its own static fields used
 * to hold the user outside a coroutine, where {@see CarriedContext} could not
 * reach them: a Queued handler run in process from a command ran as the
 * command's user, where a worker runs it as nobody.
 *
 * clear() is registered with PerRequestStateRegistry, so the framework wipes
 * it in the finally block of every Application::handleRequest and
 * QueueWorker::processPayload. Outside a coroutine the start of each one
 * clears it too (CoroutineLocal::beginRequest()): a user set before an
 * in-process handleRequest() or processPayload() is not seen inside it.
 */
final class AuthContextStore
{
    private const USER_KEY   = '__auth_user';
    private const RESULT_KEY = '__auth_result';
    private const REGISTRY_NAME = 'auth_context_store';

    private static bool $registered = false;

    public static function setUser(?AuthenticatableInterface $user): void
    {
        self::ensureRegistered();
        CoroutineLocal::set(self::USER_KEY, $user);
    }

    public static function getUser(): ?AuthenticatableInterface
    {
        $user = CoroutineLocal::get(self::USER_KEY);

        return $user instanceof AuthenticatableInterface ? $user : null;
    }

    public static function setResult(AuthResult $result): void
    {
        self::ensureRegistered();
        CoroutineLocal::set(self::RESULT_KEY, $result);
    }

    public static function getResult(): ?AuthResult
    {
        $result = CoroutineLocal::get(self::RESULT_KEY);

        return $result instanceof AuthResult ? $result : null;
    }

    public static function clear(): void
    {
        CoroutineLocal::remove(self::USER_KEY);
        CoroutineLocal::remove(self::RESULT_KEY);
    }

    /**
     * @deprecated the same as clear(), kept for callers of the old static fallback
     */
    public static function clearFallback(): void
    {
        self::clear();
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
        // Work run after the response (an Async handler) gets the request's user.
        CarriedContext::carry(self::USER_KEY, self::RESULT_KEY);
        self::$registered = true;
        PerRequestStateRegistry::register(
            self::REGISTRY_NAME,
            static function (): void {
                self::clear();
            },
        );
    }
}
