<?php

declare(strict_types=1);

namespace Semitexa\Auth\Application\Service;

use Semitexa\Auth\Application\Service\SessionAuthHandler;
use Semitexa\Core\Attribute\AsService;
use Semitexa\Core\Session\SessionInterface;

/**
 * Framework-internal bridge for authenticated session state.
 *
 * Application code (handlers, services) must go through this writer;
 * it is the only sanctioned path that may touch the raw session key
 * contract, and it does so solely to keep the SSR async server
 * (packages/semitexa-ssr/.../AsyncResourceSseServer) working while
 * it still reads the top-level `_auth_user_id` slot. Once SSR reads
 * the `auth` segment directly, the raw set()/remove() calls below
 * can be removed.
 */
#[AsService]
final class AuthSessionWriter
{
    public function setAuthenticated(
        SessionInterface $session,
        string $userId,
        string $provider,
        ?int $authenticatedAt = null,
    ): void {
        $segment = $session->getPayload(AuthSessionSegment::class);

        if (
            $authenticatedAt === null
            && $segment->getUserId() === $userId
            && $segment->getProvider() === $provider
            && $segment->getAuthenticatedAt() !== null
        ) {
            $authenticatedAt = $segment->getAuthenticatedAt();
        }

        $segment->setAuthenticated($userId, $provider, $authenticatedAt);
        $session->setPayload($segment);

        $session->set(SessionAuthHandler::SESSION_USER_KEY, $userId);
    }

    public function clear(SessionInterface $session): void
    {
        $segment = $session->getPayload(AuthSessionSegment::class);
        $segment->clear();
        $session->setPayload($segment);

        $session->remove(SessionAuthHandler::SESSION_USER_KEY);
    }
}
