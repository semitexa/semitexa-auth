<?php

declare(strict_types=1);

namespace Semitexa\Auth\Handler;

use Semitexa\Auth\Attribute\AsAuthHandler;
use Semitexa\Auth\Contract\UserProviderInterface;
use Semitexa\Core\Attributes\InjectAsReadonly;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Session\SessionInterface;

#[AsAuthHandler(priority: 0)]
class SessionAuthHandler implements AuthHandlerInterface
{
    public const SESSION_USER_KEY = '_auth_user_id';

    #[InjectAsReadonly]
    protected ?UserProviderInterface $userProvider = null;

    /** Injected by container (mutable) or by AuthBootstrapper::resolveHandler() fallback. */
    protected ?SessionInterface $session = null;

    public function setSession(SessionInterface $session): void
    {
        $this->session = $session;
    }

    public function setUserProvider(UserProviderInterface $userProvider): void
    {
        $this->userProvider = $userProvider;
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
        $userId = $this->session->get(self::SESSION_USER_KEY);

        if ($userId === null) {
            if ($hasDebugLog) {
                \Semitexa\Core\Debug\SessionDebugLog::log('SessionAuthHandler.handle', ['reason' => 'no_user_id_in_session']);
            }
            return null;
        }

        $user = $this->userProvider->findById((string) $userId);

        if ($user === null) {
            $this->session->forget(self::SESSION_USER_KEY);
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
}
