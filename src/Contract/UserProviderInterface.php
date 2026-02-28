<?php

declare(strict_types=1);

namespace Semitexa\Auth\Contract;

use Semitexa\Core\Auth\AuthenticatableInterface;

/**
 * Loads a user by their primary identifier.
 *
 * Applications register an implementation via #[AsServiceContract(of: UserProviderInterface::class)].
 * SessionAuthHandler uses this to resolve the user stored in the session.
 */
interface UserProviderInterface
{
    /**
     * Find a user by the identifier stored in the session (usually the primary key).
     * Returns null when the user no longer exists or has been disabled.
     */
    public function findById(string $id): ?AuthenticatableInterface;
}
