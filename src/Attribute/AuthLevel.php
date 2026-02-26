<?php

declare(strict_types=1);

namespace Semitexa\Auth\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS)]
final class AuthLevel
{
    public function __construct(
        public readonly string $strategy = 'first_match',
    ) {}
}
