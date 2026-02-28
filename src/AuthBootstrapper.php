<?php

declare(strict_types=1);

namespace Semitexa\Auth;

use Psr\Container\ContainerInterface;
use Semitexa\Auth\Attribute\AsAuthHandler;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Auth\Handler\AuthHandlerInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Contract\PayloadInterface;
use Semitexa\Core\Discovery\ClassDiscovery;
use Semitexa\Core\Event\EventDispatcherInterface;

final class AuthBootstrapper
{
    /** @var AuthHandlerInterface[] */
    private array $handlers = [];

    private bool $enabled;
    private string $strategy;

    public function __construct(
        private readonly ContainerInterface $container,
        ?EventDispatcherInterface $events = null,
    ) {
        $this->enabled  = getenv('AUTH_ENABLED') !== 'false';
        $this->strategy = getenv('AUTH_STRATEGY') ?: 'first_match';

        $this->discoverHandlers();
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function handle(PayloadInterface $payload): void
    {
        if (!$this->enabled) {
            return;
        }

        $manager = AuthManager::getInstance();

        if ($this->strategy === 'first_match') {
            foreach ($this->handlers as $handler) {
                $result = $handler->handle($payload);

                if ($result !== null && $result->success) {
                    $manager->setAuthResult($result);
                    return;
                }
            }
            return;
        }

        if ($this->strategy === 'all_required') {
            foreach ($this->handlers as $handler) {
                $result = $handler->handle($payload);

                if ($result === null || !$result->success) {
                    return;
                }
            }

            $user = $manager->getUser()
                ?? throw new \RuntimeException('No user set after all auth handlers succeeded.');

            $manager->setAuthResult(AuthResult::success($user));
        }
    }

    /**
     * Discover all classes marked with #[AsAuthHandler] via the composer classmap,
     * resolve each through the DI container so their dependencies are injected,
     * and sort by priority (lower value = runs first).
     */
    private function discoverHandlers(): void
    {
        $classes = ClassDiscovery::findClassesWithAttribute(AsAuthHandler::class);

        $withPriority = [];

        foreach ($classes as $class) {
            $reflection = new \ReflectionClass($class);

            if ($reflection->isAbstract() || $reflection->isInterface()) {
                continue;
            }

            if (!is_a($class, AuthHandlerInterface::class, true)) {
                continue;
            }

            $attrs    = $reflection->getAttributes(AsAuthHandler::class);
            /** @var AsAuthHandler $attr */
            $attr     = $attrs[0]->newInstance();
            $priority = $attr->priority;

            /** @var AuthHandlerInterface $handler */
            $handler = $this->container->has($class)
                ? $this->container->get($class)
                : new $class();

            $withPriority[] = [$priority, $handler];
        }

        usort($withPriority, static fn(array $a, array $b) => $a[0] <=> $b[0]);

        $this->handlers = array_column($withPriority, 1);
    }

    /**
     * Manually register a handler (useful in tests or when wiring without auto-discovery).
     */
    public function addHandler(AuthHandlerInterface $handler): void
    {
        $this->handlers[] = $handler;
    }

    /** @return AuthHandlerInterface[] */
    public function getHandlers(): array
    {
        return $this->handlers;
    }
}
