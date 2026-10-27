<?php

declare(strict_types=1);

namespace Semitexa\Auth\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Auth\Application\Service\AuthSessionSegment;
use Semitexa\Auth\Application\Service\AuthSessionWriter;
use Semitexa\Auth\Application\Service\SessionAuthHandler;
use Semitexa\Core\Session\Session;
use Semitexa\Core\Session\SessionHandlerInterface;

/**
 * Session fixation: an id planted in the browser before login must not be the
 * id the authenticated session is stored under.
 */
final class AuthSessionWriterTest extends TestCase
{
    private const PLANTED_ID = '0123456789abcdef0123456789abcdef';

    #[Test]
    public function logging_in_rotates_the_session_id(): void
    {
        $session = $this->session();

        (new AuthSessionWriter())->setAuthenticated($session, 'user-1', 'password');
        $session->save();

        self::assertNotSame(self::PLANTED_ID, $session->getId());
    }

    #[Test]
    public function refreshing_the_same_identity_keeps_the_session_id(): void
    {
        $session = $this->session();
        $writer = new AuthSessionWriter();
        $writer->setAuthenticated($session, 'user-1', 'password');
        $session->save();
        $afterLogin = $session->getId();

        $writer->setAuthenticated($session, 'user-1', 'password');
        $session->save();

        self::assertSame($afterLogin, $session->getId());
    }

    #[Test]
    public function logging_out_rotates_the_session_id(): void
    {
        $session = $this->session();
        $writer = new AuthSessionWriter();
        $writer->setAuthenticated($session, 'user-1', 'password');
        $session->save();
        $afterLogin = $session->getId();

        $writer->clear($session);
        $session->save();

        self::assertNotSame($afterLogin, $session->getId());
    }

    #[Test]
    public function a_padded_copy_of_the_same_identity_keeps_the_session_id(): void
    {
        $session = $this->session();
        $writer = new AuthSessionWriter();
        $writer->setAuthenticated($session, 'user-1', 'password');
        $session->save();
        $afterLogin = $session->getId();

        $writer->setAuthenticated($session, ' user-1 ', ' password ');
        $session->save();

        self::assertSame($afterLogin, $session->getId());
        self::assertSame('user-1', $session->get(SessionAuthHandler::SESSION_USER_KEY));
    }

    #[Test]
    public function logging_out_a_legacy_only_session_rotates_the_session_id(): void
    {
        // Signed in through the top-level key alone, with no auth segment.
        $session = $this->session();
        $session->set(SessionAuthHandler::SESSION_USER_KEY, 'user-1');
        $session->save();

        (new AuthSessionWriter())->clear($session);
        $session->save();

        self::assertNotSame(self::PLANTED_ID, $session->getId());
        self::assertFalse($session->has(SessionAuthHandler::SESSION_USER_KEY));
    }

    #[Test]
    public function the_next_request_reads_back_the_signed_in_segment(): void
    {
        $handler = $this->handler();
        $login = new Session(self::PLANTED_ID, $handler, 'semitexa_session');
        (new AuthSessionWriter())->setAuthenticated($login, 'user-1', 'password', 1_700_000_000);
        $login->save();

        $next = new Session($login->getId(), $handler, 'semitexa_session');
        $segment = $next->getPayload(AuthSessionSegment::class);

        self::assertSame('user-1', $segment->getUserId());
        self::assertSame('password', $segment->getProvider());
        self::assertSame(1_700_000_000, $segment->getAuthenticatedAt());
    }

    /** A session cookie stolen before a password change kept working after it. */
    #[Test]
    public function a_session_signed_in_with_older_credentials_is_over(): void
    {
        $handler = $this->handler();
        $login = new Session(self::PLANTED_ID, $handler, 'semitexa_session');
        (new AuthSessionWriter())->setAuthenticated($login, 'user-1', 'password', credentialStamp: '1');
        $login->save();

        $user = new StampedUser('user-1', '1');
        self::assertTrue($this->authenticate(new Session($login->getId(), $handler, 'semitexa_session'), $user)->success);

        $user->stamp = '2'; // a new password
        $after = new Session($login->getId(), $handler, 'semitexa_session');
        self::assertFalse($this->authenticate($after, $user)->success);
        self::assertFalse($after->getPayload(AuthSessionSegment::class)->isAuthenticated(), 'and signed out');
    }

    /**
     * A stamped user's session with no stamp (from before stamps) was given
     * the current one on its first request: a cookie stolen before a password
     * change, first used after it, adopted the new password and lived on.
     */
    #[Test]
    public function a_stamped_user_s_session_without_a_stamp_is_over(): void
    {
        $handler = $this->handler();
        $login = new Session(self::PLANTED_ID, $handler, 'semitexa_session');
        (new AuthSessionWriter())->setAuthenticated($login, 'user-1', 'password');
        $login->save();
        self::assertNull($login->getPayload(AuthSessionSegment::class)->getCredentialStamp(), 'precondition: no stamp recorded');

        $next = new Session($login->getId(), $handler, 'semitexa_session');
        $result = $this->authenticate($next, new StampedUser('user-1', '8'));

        self::assertFalse($result->success);
        self::assertSame('Credentials not recorded', $result->reason);
        self::assertFalse($next->getPayload(AuthSessionSegment::class)->isAuthenticated(), 'and signed out');
    }

    /** A sign-in that names no stamp gets the user's own at once, not on the session's next request. */
    #[Test]
    public function a_sign_in_without_a_stamp_takes_the_user_s_own(): void
    {
        $user = new StampedUser('user-1', '4');
        $writer = new AuthSessionWriter();
        (new \ReflectionProperty(AuthSessionWriter::class, 'users'))->setValue($writer, new class ($user) implements \Semitexa\Auth\Domain\Contract\UserProviderInterface {
            public function __construct(private StampedUser $user) {}
            public function findById(string $id): ?\Semitexa\Core\Auth\AuthenticatableInterface { return $this->user; }
        });
        $session = $this->session();

        $writer->setAuthenticated($session, 'user-1', 'password');

        self::assertSame('4', $session->getPayload(AuthSessionSegment::class)->getCredentialStamp());
    }

    /**
     * The same identity signed in again keeps its stamp unless the sign-in
     * names one: a refresh that proves nothing must not carry the session
     * across a password change, and a password sign-in passes the new one.
     */
    #[Test]
    public function the_same_identity_keeps_its_stamp_unless_the_sign_in_names_the_new_one(): void
    {
        $user = new StampedUser('user-1', '4');
        $writer = new AuthSessionWriter();
        (new \ReflectionProperty(AuthSessionWriter::class, 'users'))->setValue($writer, new class ($user) implements \Semitexa\Auth\Domain\Contract\UserProviderInterface {
            public function __construct(private StampedUser $user) {}
            public function findById(string $id): ?\Semitexa\Core\Auth\AuthenticatableInterface { return $this->user; }
        });
        $session = $this->session();
        $writer->setAuthenticated($session, 'user-1', 'password');
        $user->stamp = '5';

        $writer->setAuthenticated($session, 'user-1', 'sso');
        self::assertSame('4', $session->getPayload(AuthSessionSegment::class)->getCredentialStamp(), 'a refresh does not adopt the new password');

        $writer->setAuthenticated($session, 'user-1', 'sso', credentialStamp: $user->credentialStamp());
        self::assertSame('5', $session->getPayload(AuthSessionSegment::class)->getCredentialStamp());
    }

    /**
     * A provider whose users have no stamp (the demo's Google sign-in, which
     * signs in again on every request) cost a user lookup per request.
     */
    #[Test]
    public function signing_the_same_identity_in_again_looks_nobody_up(): void
    {
        $writer = new AuthSessionWriter();
        $lookups = new \ArrayObject();
        (new \ReflectionProperty(AuthSessionWriter::class, 'users'))->setValue($writer, new class ($lookups) implements \Semitexa\Auth\Domain\Contract\UserProviderInterface {
            public function __construct(private \ArrayObject $lookups) {}
            public function findById(string $id): ?\Semitexa\Core\Auth\AuthenticatableInterface { $this->lookups->append($id); return null; }
        });
        $session = $this->session();

        $writer->setAuthenticated($session, 'g-1', 'google');
        $writer->setAuthenticated($session, 'g-1', 'google');
        $writer->setAuthenticated($session, 'g-1', 'google');

        self::assertSame(['g-1'], $lookups->getArrayCopy(), 'once, for the new identity');
    }

    private function authenticate(Session $session, StampedUser $user): \Semitexa\Core\Auth\AuthResult
    {
        $auth = new SessionAuthHandler();
        $provider = new class ($user) implements \Semitexa\Auth\Domain\Contract\UserProviderInterface {
            public function __construct(private StampedUser $user) {}
            public function findById(string $id): ?\Semitexa\Core\Auth\AuthenticatableInterface { return $id === $this->user->getId() ? $this->user : null; }
        };
        foreach (['userProvider' => $provider, 'session' => $session, 'authWriter' => new AuthSessionWriter()] as $property => $value) {
            (new \ReflectionProperty(SessionAuthHandler::class, $property))->setValue($auth, $value);
        }

        $result = $auth->handle(new \stdClass());
        self::assertNotNull($result);

        return $result;
    }

    private function session(): Session
    {
        return new Session(self::PLANTED_ID, $this->handler(), 'semitexa_session');
    }

    private function handler(): SessionHandlerInterface
    {
        return new class implements SessionHandlerInterface {
            /** @var array<string, array<string, mixed>> */
            private array $rows = [];

            public function read(string $sessionId): array
            {
                return $this->rows[$sessionId] ?? [];
            }

            public function write(string $sessionId, array $data, int $lifetimeSeconds = 3600): void
            {
                $this->rows[$sessionId] = $data;
            }

            public function destroy(string $sessionId): void
            {
                unset($this->rows[$sessionId]);
            }
        };
    }
}

final class StampedUser implements \Semitexa\Core\Auth\AuthenticatableInterface, \Semitexa\Auth\Domain\Contract\CredentialStampedInterface
{
    public function __construct(private string $id, public string $stamp) {}
    public function getId(): string { return $this->id; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getAuthIdentifier(): string { return $this->id; }
    public function credentialStamp(): string { return $this->stamp; }
}
