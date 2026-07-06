<?php

declare(strict_types=1);

use Semitexa\Dev\Application\Service\Ai\Verify\Structure\LocalModuleStructureExtension;
use Semitexa\Dev\Application\Service\Ai\Verify\Structure\ModuleStructureRule;

if (!class_exists(LocalModuleStructureExtension::class) || !class_exists(ModuleStructureRule::class)) {
    return null;
}

return new LocalModuleStructureExtension(
    package: 'auth',
    topLevelFiles: [
        'AuthenticationMode.php',
    ],
    reason: 'semitexa-auth keeps a src/AuthenticationMode.php back-compat shim: a class_alias from the pre-refactor root FQCN Semitexa\\Auth\\AuthenticationMode onto its canonical Semitexa\\Core\\Auth\\AuthenticationMode replacement. It was deliberately restored (e5b2664) so external consumers of the old root FQCN keep resolving, and it MUST sit at src/AuthenticationMode.php so PSR-4 autoloads it when that FQCN is referenced — moving or deleting it would break the compatibility it exists to provide. Retained for one release cycle; the sole authorised root file at the source root.',
);
