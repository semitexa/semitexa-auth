<?php

declare(strict_types=1);

namespace Semitexa\Auth\Application\Service;

use Semitexa\Auth\Application\Service\SessionAuthHandler;
use Semitexa\Auth\Domain\Contract\CredentialStampedInterface;
use Semitexa\Auth\Domain\Contract\UserProviderInterface;
use Semitexa\Core\Attribute\AsService;
use Semitexa\Core\Attribute\InjectAsReadonly;
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
    /**
     * Asked for the stamp when a sign-in names none: recorded only on the
     * session's first request after it, a password changed in between
     * became the stamp, and the session outlived the change. Optional only
     * for a writer built by hand.
     */
    #[InjectAsReadonly(optional: true)]
    protected UserProviderInterface $users;

    public function setAuthenticated(
        SessionInterface $session,
        string $userId,
        string $provider,
        ?int $authenticatedAt = null,
        ?string $credentialStamp = null,
    ): void {
        // Compare in the form the segment stores (it trims), or a padded but
        // identical id would count as a new identity and rotate the session.
        $userId = trim($userId);
        $provider = trim($provider);
        $segment = $session->getPayload(AuthSessionSegment::class);

        if (
            $authenticatedAt === null
            && $segment->getUserId() === $userId
            && $segment->getProvider() === $provider
            && $segment->getAuthenticatedAt() !== null
        ) {
            $authenticatedAt = $segment->getAuthenticatedAt();
        }

        // A new identity on this session is a privilege change: rotate the
        // session id (and, with it, the CSRF token) so an id planted in the
        // browser before login — session fixation — is worthless after it.
        if ($segment->getUserId() !== $userId) {
            $session->regenerate();
        }

        // The same identity signed in again without naming a stamp keeps the
        // one it had: SessionAuthHandler would otherwise record whatever the
        // user's stamp is next, after a password change included.
        if ($credentialStamp === null && $segment->getUserId() === $userId) {
            $credentialStamp = $segment->getCredentialStamp();
        }
        if ($credentialStamp === null && isset($this->users)) {
            $found = $this->users->findById($userId);
            $credentialStamp = $found instanceof CredentialStampedInterface ? $found->credentialStamp() : null;
        }
        $segment->setAuthenticated($userId, $provider, $authenticatedAt, $credentialStamp);
        $session->setPayload($segment);

        $session->set(SessionAuthHandler::SESSION_USER_KEY, $userId);
    }

    public function clear(SessionInterface $session): void
    {
        $segment = $session->getPayload(AuthSessionSegment::class);
        // Logout is a privilege change too: the id the user was known by must
        // not stay valid for whoever holds it next.
        // A session signed in only through the legacy top-level key (no
        // hydrated segment) is still an authenticated one and rotates too.
        if (
            $segment->getUserId() !== null
            || $session->has(SessionAuthHandler::SESSION_USER_KEY)
        ) {
            $session->regenerate();
        }
        $segment->clear();
        $session->setPayload($segment);

        $session->remove(SessionAuthHandler::SESSION_USER_KEY);
    }
}
