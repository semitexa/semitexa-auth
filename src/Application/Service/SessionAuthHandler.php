<?php

declare(strict_types=1);

namespace Semitexa\Auth\Application\Service;

use Semitexa\Auth\Domain\Contract\AuthHandlerInterface;

use Semitexa\Auth\Attribute\AsAuthHandler;
use Semitexa\Auth\Domain\Contract\UserProviderInterface;
use Semitexa\Auth\Application\Service\AuthSessionSegment;
use Semitexa\Auth\Application\Service\AuthSessionWriter;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Session\SessionInterface;

#[AsAuthHandler(priority: 0)]
class SessionAuthHandler implements AuthHandlerInterface
{
    private const LEGACY_PROVIDER = 'legacy';

    /**
     * @deprecated Kept only as the raw-key contract read by the SSR async server
     *             (packages/semitexa-ssr/.../AsyncResourceSseServer) and by
     *             AuthSessionWriter's transitional bridge. Application code must
     *             never read or write it directly — use AuthSessionSegment.
     */
    public const SESSION_USER_KEY = '_auth_user_id';

    protected UserProviderInterface $userProvider;

    /** Injected by container (mutable) or by AuthBootstrapper::resolveHandler() fallback. */
    protected SessionInterface $session;

    protected AuthSessionWriter $authWriter;

    public function setSession(SessionInterface $session): void
    {
        $this->session = $session;
    }

    public function setUserProvider(UserProviderInterface $userProvider): void
    {
        $this->userProvider = $userProvider;
    }

    public function setAuthWriter(AuthSessionWriter $authWriter): void
    {
        $this->authWriter = $authWriter;
    }

    public function handle(object $payload): ?AuthResult
    {
        if (!isset($this->session) || !isset($this->userProvider)) {
            return null;
        }

        $segment = $this->session->getPayload(AuthSessionSegment::class);
        if (!$segment->isAuthenticated()) {
            $legacyUserId = $this->session->get(self::SESSION_USER_KEY);
            if (is_string($legacyUserId) && trim($legacyUserId) !== '') {
                $segment->setAuthenticated(trim($legacyUserId), self::LEGACY_PROVIDER);
                $this->session->setPayload($segment);
            }
        }

        if (!$segment->isAuthenticated()) {
            return null;
        }

        $userId = (string) $segment->getUserId();
        $user = $this->userProvider->findById($userId);

        if ($user === null) {
            $this->clearAuthSession();
            return AuthResult::failed('User not found');
        }

        return AuthResult::success($user);
    }

    private function clearAuthSession(): void
    {
        if (!isset($this->session)) {
            return;
        }

        if (isset($this->authWriter)) {
            $this->authWriter->clear($this->session);
            return;
        }

        $segment = $this->session->getPayload(AuthSessionSegment::class);
        $segment->clear();
        $this->session->setPayload($segment);
        $this->session->remove(self::SESSION_USER_KEY);
    }
}
