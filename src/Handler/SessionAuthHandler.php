<?php

declare(strict_types=1);

namespace Semitexa\Auth\Handler;

use Semitexa\Core\Contract\PayloadInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Auth\Attribute\AuthLevel;

#[AuthLevel(strategy: 'first_match')]
class SessionAuthHandler implements AuthHandlerInterface
{
    private const SESSION_USER_KEY = '_auth_user_id';

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

        $user = $this->resolveUser($userId);
        
        if ($user === null) {
            $session->forget(self::SESSION_USER_KEY);
            return AuthResult::failed('User not found');
        }

        return AuthResult::success($user);
    }

    private function resolveUser(string $userId): ?object
    {
        return null;
    }
}
