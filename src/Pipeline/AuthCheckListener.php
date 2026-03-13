<?php

declare(strict_types=1);

namespace Semitexa\Auth\Pipeline;

use Psr\Container\ContainerInterface;
use Semitexa\Auth\AuthBootstrapper;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Core\Attributes\AsPipelineListener;
use Semitexa\Core\Attributes\InjectAsReadonly;
use Semitexa\Core\Attributes\RequiresAuth;
use Semitexa\Core\Attributes\RequiresPermission;
use Semitexa\Core\Pipeline\AuthCheck;
use Semitexa\Core\Pipeline\Exception\AccessDeniedException;
use Semitexa\Core\Pipeline\Exception\AuthenticationRequiredException;
use Semitexa\Core\Pipeline\PipelineListenerInterface;
use Semitexa\Core\Pipeline\RequestPipelineContext;

/**
 * Wraps AuthBootstrapper::handle() for the pipeline.
 * AuthBootstrapper solves a real problem (strategies, handler iteration) — this listener
 * provides the "where" (AuthCheck phase); bootstrapper provides the "how".
 */
#[AsPipelineListener(phase: AuthCheck::class, priority: 0)]
final class AuthCheckListener implements PipelineListenerInterface
{
    #[InjectAsReadonly]
    protected ?ContainerInterface $container = null;

    public function handle(RequestPipelineContext $context): void
    {
        $authBootstrapper = $context->authBootstrapper instanceof AuthBootstrapper ? $context->authBootstrapper : null;

        if ($authBootstrapper === null || !$authBootstrapper->isEnabled()) {
            $this->checkRequiresAuth($context);
            $this->checkRequiresPermission($context);
            return;
        }

        $authBootstrapper->handle($context->requestDto);

        $context->authResult = AuthManager::getInstance()->getLastResult();

        $this->checkRequiresAuth($context);
        $this->checkRequiresPermission($context);
    }

    private function checkRequiresAuth(RequestPipelineContext $context): void
    {
        if (!$this->hasRequiresAuth($context->requestDto)) {
            return;
        }

        if (AuthManager::getInstance()->isGuest()) {
            throw new AuthenticationRequiredException('Authentication required');
        }
    }

    private function checkRequiresPermission(RequestPipelineContext $context): void
    {
        $permissions = $this->getRequiredPermissions($context->requestDto);

        if ($permissions === []) {
            return;
        }

        $user = AuthManager::getInstance()->getUser();

        if ($user === null) {
            throw new AuthenticationRequiredException('Authentication required');
        }

        try {
            $rbacClass = 'Semitexa\\Platform\\User\\Domain\\Service\\RbacServiceInterface';
            if (!interface_exists($rbacClass) && !class_exists($rbacClass)) {
                return;
            }
            $rbac = $this->container?->get($rbacClass);
        } catch (\Throwable) {
            $rbac = null;
        }

        if ($rbac === null) {
            return;
        }

        foreach ($permissions as $permission) {
            if (!$rbac->userHasPermission($user->getId(), $permission)) {
                throw new AccessDeniedException("Missing permission: {$permission}");
            }
        }
    }

    /**
     * Walk the class hierarchy to find #[RequiresAuth].
     * Registry-generated DTOs extend the base payload class that carries the attribute,
     * so we must check parent classes as well — PHP's getAttributes() is not inherited.
     */
    private function hasRequiresAuth(object $dto): bool
    {
        $ref = new \ReflectionClass($dto);
        while ($ref !== false) {
            if ($ref->getAttributes(RequiresAuth::class) !== []) {
                return true;
            }
            $ref = $ref->getParentClass();
        }
        return false;
    }

    /**
     * Collect all #[RequiresPermission] slugs from the class hierarchy.
     *
     * @return list<string>
     */
    private function getRequiredPermissions(object $dto): array
    {
        $permissions = [];
        $ref = new \ReflectionClass($dto);
        while ($ref !== false) {
            foreach ($ref->getAttributes(RequiresPermission::class) as $attr) {
                $permissions[] = $attr->newInstance()->permission;
            }
            $ref = $ref->getParentClass();
        }
        return $permissions;
    }
}
