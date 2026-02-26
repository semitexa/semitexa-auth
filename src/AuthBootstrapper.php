<?php

declare(strict_types=1);

namespace Semitexa\Auth;

use Semitexa\Core\Contract\PayloadInterface;
use Semitexa\Core\Event\EventDispatcherInterface;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Auth\Handler\AuthHandlerInterface;

final class AuthBootstrapper
{
    /** @var AuthHandlerInterface[] */
    private array $handlers = [];
    private ?EventDispatcherInterface $events = null;
    private bool $enabled;
    private string $strategy;

    public function __construct(?EventDispatcherInterface $events = null)
    {
        $this->events = $events;
        $this->enabled = getenv('AUTH_ENABLED') !== 'false';
        $this->strategy = getenv('AUTH_STRATEGY') ?? 'first_match';
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
        } elseif ($this->strategy === 'all_required') {
            $allSuccess = true;
            
            foreach ($this->handlers as $handler) {
                $result = $handler->handle($payload);
                
                if ($result === null || !$result->success) {
                    $allSuccess = false;
                    break;
                }
            }
            
            if ($allSuccess) {
                $manager->setAuthResult(\Semitexa\Core\Auth\AuthResult::success(
                    $manager->getUser() ?? throw new \RuntimeException('No user after all handlers succeeded')
                ));
            }
        }
    }

    private function discoverHandlers(): void
    {
        $classes = get_declared_classes();

        foreach ($classes as $class) {
            if (!is_a($class, AuthHandlerInterface::class, true)) {
                continue;
            }

            $reflection = new \ReflectionClass($class);
            
            if ($reflection->isAbstract() || $reflection->isInterface()) {
                continue;
            }

            $this->handlers[] = new $class();
        }
    }

    public function addHandler(AuthHandlerInterface $handler): void
    {
        $this->handlers[] = $handler;
    }

    public function getHandlers(): array
    {
        return $this->handlers;
    }
}
