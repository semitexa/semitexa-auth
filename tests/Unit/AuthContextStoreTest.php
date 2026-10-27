<?php

declare(strict_types=1);

namespace Semitexa\Auth\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Auth\Context\AuthContextStore;
use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Lifecycle\RequestContextSnapshot;

/**
 * Outside a coroutine the user sat in static fields CarriedContext could not
 * reach: a Queued handler run in process from a command ran as the command's
 * user, where a worker runs it as nobody.
 */
final class AuthContextStoreTest extends TestCase
{
    protected function tearDown(): void
    {
        AuthContextStore::clear();
    }

    #[Test]
    public function work_run_as_a_worker_would_has_no_user_and_the_caller_gets_its_back(): void
    {
        $user = new class implements AuthenticatableInterface {
            public function getId(): string { return 'u-1'; }
            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): mixed { return 'u-1'; }
        };
        AuthContextStore::setUser($user);

        $seen = RequestContextSnapshot::none(null)->run(static fn (): ?AuthenticatableInterface => AuthContextStore::getUser());

        self::assertNull($seen);
        self::assertSame($user, AuthContextStore::getUser());
    }

    #[Test]
    public function a_captured_request_carries_its_user_outside_a_coroutine_too(): void
    {
        $user = new class implements AuthenticatableInterface {
            public function getId(): string { return 'u-2'; }
            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): mixed { return 'u-2'; }
        };
        AuthContextStore::setUser($user);
        $snapshot = RequestContextSnapshot::capture(null);
        AuthContextStore::clear();

        self::assertSame($user, $snapshot->run(static fn (): ?AuthenticatableInterface => AuthContextStore::getUser()));
        self::assertNull(AuthContextStore::getUser());
    }
}
