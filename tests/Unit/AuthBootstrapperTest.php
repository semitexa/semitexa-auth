<?php

declare(strict_types=1);

namespace Semitexa\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Semitexa\Auth\AuthBootstrapper;
use Semitexa\Auth\Handler\AuthHandlerInterface;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthenticationMode;
use Semitexa\Core\Auth\GuestAuthContext;
use Semitexa\Core\Log\LoggerInterface;

/**
 * Boundary tests for the Core/Auth inversion. Verifies the bootstrapper only
 * depends on Core-owned contracts and honours the Mandatory/BestEffort contract
 * defined by AuthBootstrapperInterface.
 */
final class AuthBootstrapperTest extends TestCase
{
    public function testImplementsCoreInterface(): void
    {
        $bootstrapper = $this->makeBootstrapper();
        self::assertInstanceOf(AuthBootstrapperInterface::class, $bootstrapper);
    }

    public function testSuccessfulHandlerPopulatesContextAndReturnsResult(): void
    {
        $user = $this->makeUser('u-1');
        $handler = $this->makeHandler(AuthResult::success($user));
        $context = new RecordingAuthContext();

        $bootstrapper = $this->makeBootstrapper(authContext: $context);
        $bootstrapper->addHandler($handler);

        $result = $bootstrapper->handle(new \stdClass(), AuthenticationMode::Mandatory);

        self::assertNotNull($result);
        self::assertTrue($result->success);
        self::assertSame($user, $context->getUser());
        self::assertSame($result, $context->getLastResult());
    }

    public function testMandatoryModePropagatesHandlerException(): void
    {
        $handler = $this->makeThrowingHandler(new \RuntimeException('boom'));
        $bootstrapper = $this->makeBootstrapper(authContext: new RecordingAuthContext());
        $bootstrapper->addHandler($handler);

        $this->expectException(\RuntimeException::class);
        $bootstrapper->handle(new \stdClass(), AuthenticationMode::Mandatory);
    }

    public function testBestEffortDegradesToGuestAndLogsWhenHandlerThrows(): void
    {
        $handler = $this->makeThrowingHandler(new \RuntimeException('boom'));
        $context = new RecordingAuthContext();
        $logger = new RecordingLogger();

        $bootstrapper = $this->makeBootstrapper(authContext: $context, logger: $logger);
        $bootstrapper->addHandler($handler);

        $result = $bootstrapper->handle(new \stdClass(), AuthenticationMode::BestEffort);

        self::assertNull($result);
        self::assertNull($context->getUser());
        self::assertNotEmpty($logger->records, 'BestEffort degradation must be observable through the logger');
        self::assertSame('warning', $logger->records[0]['level']);
        self::assertSame(get_class($handler), $logger->records[0]['context']['handler']);
        self::assertSame(\RuntimeException::class, $logger->records[0]['context']['exception']);
    }

    public function testBestEffortStillPropagatesPhpErrors(): void
    {
        $handler = $this->makeThrowingHandler(new \TypeError('boom'));
        $bootstrapper = $this->makeBootstrapper(authContext: new RecordingAuthContext());
        $bootstrapper->addHandler($handler);

        $this->expectException(\TypeError::class);
        $bootstrapper->handle(new \stdClass(), AuthenticationMode::BestEffort);
    }

    public function testLegacyConstructorArgumentOrderStillWorks(): void
    {
        putenv('AUTH_ENABLED=true');
        putenv('AUTH_STRATEGY=first_match');

        $container = new NullContainer();
        $legacy = new AuthBootstrapper(
            $container,
            new NullClassDiscovery(),
            new \stdClass(),
            $container,
        );

        self::assertTrue($legacy->isEnabled());
    }

    public function testAllRequiredStrategyFailsIfAnyHandlerReturnsFailure(): void
    {
        $user = $this->makeUser('u-1');
        $okHandler = $this->makeHandler(AuthResult::success($user));
        $failHandler = $this->makeHandler(AuthResult::failed('invalid'));

        $bootstrapper = $this->makeBootstrapper(
            strategy: 'all_required',
            authContext: new RecordingAuthContext(),
        );
        $bootstrapper->addHandler($okHandler);
        $bootstrapper->addHandler($failHandler);

        $result = $bootstrapper->handle(new \stdClass(), AuthenticationMode::Mandatory);
        self::assertNull($result);
    }

    public function testDisabledBootstrapperReturnsNullWithoutInvokingHandlers(): void
    {
        $handler = $this->makeHandler(AuthResult::success($this->makeUser('u-1')));
        $bootstrapper = $this->makeBootstrapper(enabled: false);
        $bootstrapper->addHandler($handler);

        self::assertFalse($bootstrapper->isEnabled());
        self::assertNull($bootstrapper->handle(new \stdClass(), AuthenticationMode::Mandatory));
    }

    // -------------------- helpers --------------------

    protected function tearDown(): void
    {
        putenv('AUTH_ENABLED');
        putenv('AUTH_STRATEGY');
        parent::tearDown();
    }

    private function makeBootstrapper(
        ?AuthContextInterface $authContext = null,
        ?LoggerInterface $logger = null,
        bool $enabled = true,
        string $strategy = 'first_match',
    ): AuthBootstrapper {
        putenv('AUTH_ENABLED=' . ($enabled ? 'true' : 'false'));
        putenv('AUTH_STRATEGY=' . $strategy);

        $container = new NullContainer();

        return new AuthBootstrapper(
            container: $container,
            requestScopedContainer: null,
            classDiscovery: new NullClassDiscovery(),
            authContext: $authContext ?? GuestAuthContext::getInstance(),
            logger: $logger,
        );
    }

    private function makeUser(string $id): AuthenticatableInterface
    {
        return new class($id) implements AuthenticatableInterface {
            public function __construct(private readonly string $id) {}

            public function getId(): string { return $this->id; }
            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): mixed { return $this->id; }
        };
    }

    private function makeHandler(?AuthResult $result): AuthHandlerInterface
    {
        return new class($result) implements AuthHandlerInterface {
            public function __construct(private readonly ?AuthResult $result) {}
            public function handle(object $payload): ?AuthResult { return $this->result; }
        };
    }

    private function makeThrowingHandler(\Throwable $exception): AuthHandlerInterface
    {
        return new class($exception) implements AuthHandlerInterface {
            public function __construct(private readonly \Throwable $exception) {}
            public function handle(object $payload): ?AuthResult { throw $this->exception; }
        };
    }
}

/**
 * Minimal in-memory AuthContextInterface. Avoids the static AuthManager
 * singleton so each test owns its own context instance.
 */
final class RecordingAuthContext implements AuthContextInterface
{
    private ?AuthenticatableInterface $user = null;
    private ?AuthResult $lastResult = null;

    public function getUser(): ?AuthenticatableInterface { return $this->user; }
    public function isGuest(): bool { return $this->user === null; }
    public function setUser(?AuthenticatableInterface $user): void { $this->user = $user; }

    public function resetToGuest(): void
    {
        $this->user = null;
        $this->lastResult = null;
    }

    public function setAuthResult(AuthResult $result): void
    {
        $this->lastResult = $result;
        $this->user = $result->success ? $result->user : null;
    }

    public function getLastResult(): ?AuthResult { return $this->lastResult; }

    public static function get(): ?self { return null; }
    public static function getOrFail(): self
    {
        throw new \LogicException('RecordingAuthContext is per-test; use the instance directly.');
    }
}

final class RecordingLogger implements LoggerInterface
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    public array $records = [];

    public function critical(string $message, array $context = []): void { $this->record('critical', $message, $context); }
    public function error(string $message, array $context = []): void { $this->record('error', $message, $context); }
    public function warning(string $message, array $context = []): void { $this->record('warning', $message, $context); }
    public function notice(string $message, array $context = []): void { $this->record('notice', $message, $context); }
    public function info(string $message, array $context = []): void { $this->record('info', $message, $context); }
    public function debug(string $message, array $context = []): void { $this->record('debug', $message, $context); }

    private function record(string $level, string $message, array $context): void
    {
        $this->records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }
}

final class NullContainer implements ContainerInterface
{
    public function get(string $id): mixed { throw new \RuntimeException("No binding for {$id}"); }
    public function has(string $id): bool { return false; }
}

final class NullClassDiscovery extends \Semitexa\Core\Discovery\ClassDiscovery
{
    public function initialize(): void {}
    public function findClassesWithAttribute(string $attributeClass): array { return []; }
}
