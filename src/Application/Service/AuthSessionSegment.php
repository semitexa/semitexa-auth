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

    /**
     * Session hydration only. The session restores a segment through one-
     * argument setters named after its keys; without these, every request read
     * back an EMPTY segment, so the original sign-in time was lost and auth
     * fell through to the legacy `_auth_user_id` key. Use setAuthenticated().
     *
     * @internal
     */
    public function setUserId(?string $userId): void
    {
        $this->userId = $userId;
    }

    /** @internal session hydration only — see setUserId(). */
    public function setProvider(?string $provider): void
    {
        $this->provider = $provider;
    }

    /** @internal session hydration only — see setUserId(). */
    public function setAuthenticatedAt(?int $authenticatedAt): void
    {
        $this->authenticatedAt = $authenticatedAt;
    }

    public function clear(): void
    {
        $this->userId = null;
        $this->provider = null;
        $this->authenticatedAt = null;
    }
}
