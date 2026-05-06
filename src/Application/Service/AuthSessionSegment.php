<?php

declare(strict_types=1);

namespace Semitexa\Auth\Application\Service;

use Semitexa\Core\Session\Attribute\SessionSegment;

#[SessionSegment('auth')]
final class AuthSessionSegment
{
    private ?string $userId = null;
    private ?string $provider = null;
    private ?int $authenticatedAt = null;

    public function getUserId(): ?string
    {
        return $this->userId;
    }

    public function getProvider(): ?string
    {
        return $this->provider;
    }

    public function getAuthenticatedAt(): ?int
    {
        return $this->authenticatedAt;
    }

    public function isAuthenticated(): bool
    {
        return $this->userId !== null && $this->userId !== '';
    }

    public function setAuthenticated(string $userId, string $provider, ?int $authenticatedAt = null): void
    {
        $userId = trim($userId);
        $provider = trim($provider);

        if ($userId === '') {
            throw new \InvalidArgumentException('AuthSessionSegment userId must be a non-empty string.');
        }
        if ($provider === '') {
            throw new \InvalidArgumentException('AuthSessionSegment provider must be a non-empty string.');
        }

        $this->userId = $userId;
        $this->provider = $provider;
        $this->authenticatedAt = $authenticatedAt ?? time();
    }

    public function clear(): void
    {
        $this->userId = null;
        $this->provider = null;
        $this->authenticatedAt = null;
    }
}
