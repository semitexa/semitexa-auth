<?php

declare(strict_types=1);

namespace Semitexa\Auth;

use Semitexa\Core\Auth\AuthenticationMode as CoreAuthenticationMode;

/**
 * @deprecated Use Semitexa\Core\Auth\AuthenticationMode instead.
 */
if (!class_exists(AuthenticationMode::class, false)) {
    class_alias(CoreAuthenticationMode::class, AuthenticationMode::class);
}
