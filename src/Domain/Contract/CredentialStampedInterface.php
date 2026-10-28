<?php

declare(strict_types=1);

namespace Semitexa\Auth\Domain\Contract;

/**
 * A signed-in user whose credentials can change under a live session.
 *
 * The session remembers the stamp it was signed in with; once the user's
 * stamp differs — a new password, a reset — SessionAuthHandler ends that
 * session. Without it, a session cookie stolen before a password change kept
 * working after it, though changing the password is what someone does to
 * lock an intruder out.
 */
interface CredentialStampedInterface
{
    /** Changes whenever the credentials do; opaque, compared for equality only. */
    public function credentialStamp(): string;
}
