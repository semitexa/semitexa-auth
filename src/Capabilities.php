<?php

declare(strict_types=1);

namespace Semitexa\Auth;

use Semitexa\Core\Attribute\Capability;

/**
 * What this package offers, for the capability catalog.
 *
 * Without this the package is invisible to anyone whose project has not
 * installed it - which is precisely the audience worth telling, since they are
 * the ones about to build it by hand. The convention is one `Capabilities` class
 * per package: a definite place to look, and a definite place for a guard to
 * check.
 *
 * Nothing reads this at runtime.
 */
#[Capability(
    id: 'auth.authentication',
    summary: 'Credential flows, sessions and access tokens behind an auth handler contract.',
    useWhen: 'The application needs to know who is calling before it decides anything else.',
    avoidWhen: 'The question is what a known subject may do - that is semitexa/authorization.',
    replaces: [
        'a password_verify call and a $_SESSION write in a login handler',
        'a token check copy-pasted into each protected route',
    ],
    seeAlso: 'semitexa/authorization',
)]
final class Capabilities
{
}
