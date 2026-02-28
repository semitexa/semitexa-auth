<?php

declare(strict_types=1);

namespace Semitexa\Auth\Handler;

use Semitexa\Auth\Attribute\AsAuthHandler;
use Semitexa\Auth\Contract\UserProviderInterface;
use Semitexa\Core\Attributes\InjectAsReadonly;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Contract\PayloadInterface;

#[AsAuthHandler(priority: 0)]
class SessionAuthHandler implements AuthHandlerInterface
{
    private const SESSION_USER_KEY = '_auth_user_id';

    #[InjectAsReadonly]
    protected UserProviderInterface $userProvider;

    public function handle(PayloadInterface $payload): ?AuthResult
    {
        $session = $payload->getSession();

        if ($session === null) {
            return null;
        }

        $userId = $session->get(self::SESSION_USER_KEY);

        if ($userId === null) {
            return null;
        }

        $user = $this->userProvider->findById((string) $userId);

        if ($user === null) {
            $session->forget(self::SESSION_USER_KEY);
            return AuthResult::failed('User not found');
        }

        return AuthResult::success($user);
    }
}
