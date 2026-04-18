<?php

declare(strict_types=1);

namespace Semitexa\Auth;

use Psr\Container\ContainerInterface;
use Semitexa\Auth\Attribute\AsAuthHandler;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Auth\Handler\AuthHandlerInterface;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Auth\AuthenticationMode;
use Semitexa\Core\Discovery\ClassDiscovery;
use Semitexa\Core\Environment;
use Semitexa\Core\Log\LoggerInterface;
use Semitexa\Core\Session\SessionInterface;

final class AuthBootstrapper implements AuthBootstrapperInterface
{
    /** @var list<class-string<AuthHandlerInterface>> Cached discovery result (worker-scoped) */
    private ?array $discoveredHandlerClasses = null;

    /** @var list<class-string<AuthHandlerInterface>|AuthHandlerInterface> */
    private array $handlers = [];

    private bool $enabled;
    private string $strategy;
    private readonly ClassDiscovery $classDiscovery;

    /**
     * Explicit, non-overloaded constructor. Each parameter has a single role; no
     * runtime argument-swapping.
     *
     * @param AuthContextInterface|null $authContext When null, falls back to the AuthManager
     *        singleton. DI-constructed bootstrappers should always pass an explicit instance.
     * @param LoggerInterface|null $logger When supplied, BestEffort degradation is logged so
     *        public-endpoint failures are no longer silent.
     */
    public function __construct(
        private readonly ContainerInterface $container,
        private readonly ?ContainerInterface $requestScopedContainer = null,
        ?ClassDiscovery $classDiscovery = null,
        private readonly ?AuthContextInterface $authContext = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->classDiscovery = $classDiscovery ?? new ClassDiscovery();
        $this->enabled  = Environment::getEnvValue('AUTH_ENABLED', 'true') !== 'false';
        $this->strategy = Environment::getEnvValue('AUTH_STRATEGY', 'first_match') ?? 'first_match';

        $this->discoverHandlers();
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function handle(object $payload, AuthenticationMode $mode = AuthenticationMode::Mandatory): ?AuthResult
    {
        if (!$this->enabled) {
            return null;
        }

        $manager = $this->resolveAuthContext();
        // Reset auth state for this request. In Swoole each coroutine has isolated context,
        // but in CLI/test mode a static fallback persists across requests — clear it here
        // so each auth check starts from a guest state.
        $manager->resetToGuest();

        if ($this->strategy === 'first_match') {
            foreach ($this->handlers as $handlerOrClass) {
                $handler = $handlerOrClass instanceof AuthHandlerInterface
                    ? $handlerOrClass
                    : $this->resolveHandler($handlerOrClass);
                try {
                    $result = $handler->handle($payload);
                } catch (\Throwable $e) {
                    if ($mode === AuthenticationMode::BestEffort) {
                        $manager->resetToGuest();
                        $this->logDegradation('Auth handler threw in BestEffort mode; degrading to guest.', $handler::class, $e);
                        // Degrade to guest — public endpoint must never fail due to bad credentials
                        continue;
                    }
                    throw $e;
                }

                if ($result !== null && $result->success) {
                    $manager->setAuthResult($result);

                    return $result;
                }
            }

            return null;
        }

        if ($this->strategy === 'all_required') {
            foreach ($this->handlers as $handlerOrClass) {
                $handler = $handlerOrClass instanceof AuthHandlerInterface
                    ? $handlerOrClass
                    : $this->resolveHandler($handlerOrClass);
                try {
                    $result = $handler->handle($payload);
                } catch (\Throwable $e) {
                    if ($mode === AuthenticationMode::BestEffort) {
                        $manager->resetToGuest();
                        $this->logDegradation('Auth handler threw in BestEffort mode; degrading to guest.', $handler::class, $e);

                        return null;
                    }
                    throw $e;
                }

                if ($result === null || !$result->success) {
                    return null;
                }
            }

            $user = $manager->getUser()
                ?? throw new \RuntimeException('No user set after all auth handlers succeeded.');

            $result = AuthResult::success($user);
            $manager->setAuthResult($result);

            return $result;
        }

        return null;
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
                // Handler not in container or not resolvable — try main container next.
            }
        }
        if ($handler === null && $this->container->has($class)) {
            $handler = $this->container->get($class);
        }
        if ($handler === null) {
            $handler = new $class();
        }

        if (!$handler instanceof AuthHandlerInterface) {
            throw new \RuntimeException("Resolved auth handler {$class} must implement " . AuthHandlerInterface::class . '.');
        }

        if ($this->requestScopedContainer !== null && method_exists($handler, 'setSession')) {
            try {
                $handler->setSession($this->requestScopedContainer->get(SessionInterface::class));
            } catch (\Throwable) {
                // Session not in request scope; handler will treat as guest in handle()
            }
        }

        if (method_exists($handler, 'setUserProvider')) {
            try {
                $provider = $this->container->get(\Semitexa\Auth\Contract\UserProviderInterface::class);
                $handler->setUserProvider($provider);
            } catch (\Throwable) {
                // UserProvider not registered; handler will bail out gracefully
            }
        }

        return $handler;
    }

    /**
     * Discover handler classes marked with #[AsAuthHandler].
     * Handlers are resolved lazily in handle() so request-scoped dependencies are available.
     */
    private function discoverHandlers(): void
    {
        if ($this->discoveredHandlerClasses !== null) {
            $this->handlers = $this->discoveredHandlerClasses;
            return;
        }

        $classes = $this->classDiscovery->findClassesWithAttribute(AsAuthHandler::class);

        $withPriority = [];

        foreach ($classes as $class) {
            if (!class_exists($class)) {
                continue;
            }

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

        $this->discoveredHandlerClasses = array_column($withPriority, 1);
        $this->handlers = $this->discoveredHandlerClasses;
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

    /**
     * Resolve the AuthContextInterface this bootstrapper should mutate.
     * Falls back to the AuthManager singleton only when no context was injected,
     * preserving behavior for legacy construction paths.
     */
    private function resolveAuthContext(): AuthContextInterface
    {
        if ($this->authContext !== null) {
            return $this->authContext;
        }

        return AuthManager::getInstance();
    }

    private function logDegradation(string $message, string $handlerClass, \Throwable $e): void
    {
        if ($this->logger === null) {
            return;
        }

        $this->logger->warning($message, [
            'handler' => $handlerClass,
            'exception' => $e::class,
            'message' => $e->getMessage(),
        ]);
    }
}
