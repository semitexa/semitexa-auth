<?php

declare(strict_types=1);

namespace Semitexa\Auth\Handler;

use Semitexa\Auth\Attribute\AsAuthHandler;
use Semitexa\Auth\Contract\UserProviderInterface;
use Semitexa\Auth\Session\AuthSessionSegment;
use Semitexa\Auth\Session\AuthSessionWriter;
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

    protected ?UserProviderInterface $userProvider = null;

    /** Injected by container (mutable) or by AuthBootstrapper::resolveHandler() fallback. */
    protected ?SessionInterface $session = null;

    protected ?AuthSessionWriter $authWriter = null;

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
        $hasDebugLog = class_exists(\Semitexa\Core\Debug\SessionDebugLog::class);

        if ($hasDebugLog) {
            \Semitexa\Core\Debug\SessionDebugLog::log('SessionAuthHandler.handle.entry', [
                'has_session' => $this->session !== null,
                'has_user_provider' => $this->userProvider !== null,
            ]);
        }
        if ($this->session === null || $this->userProvider === null) {
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
            if ($hasDebugLog) {
                \Semitexa\Core\Debug\SessionDebugLog::log('SessionAuthHandler.handle', ['reason' => 'no_user_id_in_session']);
            }
            return null;
        }

        $userId = (string) $segment->getUserId();
        $user = $this->userProvider->findById($userId);

        if ($user === null) {
            $this->clearAuthSession();
            if ($hasDebugLog) {
                \Semitexa\Core\Debug\SessionDebugLog::log('SessionAuthHandler.handle', ['reason' => 'user_not_found', 'user_id' => $userId]);
            }
            return AuthResult::failed('User not found');
        }

        if ($hasDebugLog) {
            \Semitexa\Core\Debug\SessionDebugLog::log('SessionAuthHandler.handle', ['reason' => 'success', 'user_id' => $userId]);
        }
        return AuthResult::success($user);
    }

    private function clearAuthSession(): void
    {
        if ($this->session === null) {
            return;
        }

        if ($this->authWriter !== null) {
            $this->authWriter->clear($this->session);
            return;
        }

        $segment = $this->session->getPayload(AuthSessionSegment::class);
        $segment->clear();
        $this->session->setPayload($segment);
        $this->session->remove(self::SESSION_USER_KEY);
    }
}
