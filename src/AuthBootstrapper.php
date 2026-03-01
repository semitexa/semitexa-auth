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
use Semitexa\Core\Session\SessionInterface;

final class AuthBootstrapper
{
    /** @var list<class-string<AuthHandlerInterface>|AuthHandlerInterface> */
    private array $handlers = [];

    private bool $enabled;
    private string $strategy;

    public function __construct(
        private readonly ContainerInterface $container,
        ?EventDispatcherInterface $events = null,
        private readonly ?ContainerInterface $requestScopedContainer = null,
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
            foreach ($this->handlers as $handlerOrClass) {
                $handler = $handlerOrClass instanceof AuthHandlerInterface
                    ? $handlerOrClass
                    : $this->resolveHandler($handlerOrClass);
                $result = $handler->handle($payload);

                if ($result !== null && $result->success) {
                    $manager->setAuthResult($result);
                    return;
                }
            }
            return;
        }

        if ($this->strategy === 'all_required') {
            foreach ($this->handlers as $handlerOrClass) {
                $handler = $handlerOrClass instanceof AuthHandlerInterface
                    ? $handlerOrClass
                    : $this->resolveHandler($handlerOrClass);
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
     * Resolve handler from container (per request) so request-scoped deps (e.g. Session) are injected.
     * Prefer requestScopedContainer so the same container that has Session is used; then setSession() fallback.
     */
    private function resolveHandler(string $class): AuthHandlerInterface
    {
        $handler = null;
        if ($this->requestScopedContainer !== null) {
            try {
                $handler = $this->requestScopedContainer->get($class);
            } catch (\Throwable) {
                // Handler not in container or not resolvable
            }
        }
        if ($handler === null && $this->container->has($class)) {
            $handler = $this->container->get($class);
        }
        if ($handler === null) {
            $handler = new $class();
        }

        if ($this->requestScopedContainer !== null && method_exists($handler, 'setSession')) {
            try {
                $handler->setSession($this->requestScopedContainer->get(SessionInterface::class));
            } catch (\Throwable) {
                // Session not in request scope; handler will treat as guest in handle()
            }
        }
        return $handler;
    }

    /**
     * Discover handler classes marked with #[AsAuthHandler]. Handlers are resolved lazily in handle()
     * so request-scoped dependencies (Session, etc.) are available.
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

            $withPriority[] = [$priority, $class];
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

    /** @return list<class-string<AuthHandlerInterface>|AuthHandlerInterface> */
    public function getHandlers(): array
    {
        return $this->handlers;
    }
}
