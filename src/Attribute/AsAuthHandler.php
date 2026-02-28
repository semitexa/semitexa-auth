<?php

declare(strict_types=1);

namespace Semitexa\Auth\Attribute;

use Attribute;

/**
 * Marks a class as an authentication handler.
 *
 * Classes with this attribute are auto-discovered by AuthBootstrapper and
 * instantiated through the DI container, so constructor or property
 * injection (via #[InjectAsReadonly] / #[InjectAsMutable]) works normally.
 *
 * The optional $priority controls the order handlers are tried.
 * Lower values run first. Defaults to 0.
 *
 * Example:
 *
 *   #[AsAuthHandler(priority: 10)]
 *   class JwtAuthHandler implements AuthHandlerInterface
 *   {
 *       #[InjectAsReadonly]
 *       protected UserRepositoryInterface $users;
 *       ...
 *   }
 */
#[Attribute(Attribute::TARGET_CLASS)]
final class AsAuthHandler
{
    public function __construct(
        public readonly int $priority = 0,
    ) {}
}
