<?php

declare(strict_types=1);

namespace Semitexa\Auth\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Auth\Application\Service\AuthSessionSegment;
use Semitexa\Auth\Application\Service\AuthSessionWriter;
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
