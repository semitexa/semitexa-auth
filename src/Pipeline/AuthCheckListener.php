<?php

declare(strict_types=1);

namespace Semitexa\Auth\Pipeline;

use Semitexa\Auth\AuthBootstrapper;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Core\Attributes\AsPipelineListener;
use Semitexa\Core\Attributes\RequiresAuth;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Contract\PayloadInterface;
use Semitexa\Core\Pipeline\AuthCheck;
use Semitexa\Core\Pipeline\Exception\AuthenticationRequiredException;
use Semitexa\Core\Pipeline\PipelineListenerInterface;
use Semitexa\Core\Pipeline\RequestPipelineContext;

#[AsPipelineListener(phase: AuthCheck::class, priority: 0)]
final class AuthCheckListener implements PipelineListenerInterface
{
    public function handle(RequestPipelineContext $context): void
    {
        $authBootstrapper = $context->authBootstrapper instanceof AuthBootstrapper ? $context->authBootstrapper : null;
        $requestScopedContainer = $context->requestScopedContainer;

        $manager = AuthManager::getInstance();
        if ($requestScopedContainer !== null) {
            $requestScopedContainer->set(AuthContextInterface::class, $manager);
        }

        if ($authBootstrapper === null || !$authBootstrapper->isEnabled()) {
            $this->checkRequiresAuth($context);
            return;
        }

        if ($context->requestDto instanceof PayloadInterface) {
            $authBootstrapper->handle($context->requestDto);
        }

        $context->authResult = $manager->getLastResult();

        $this->checkRequiresAuth($context);
    }

    private function checkRequiresAuth(RequestPipelineContext $context): void
    {
        $ref = new \ReflectionClass($context->requestDto);
        $attrs = $ref->getAttributes(RequiresAuth::class);
        if ($attrs === []) {
            return;
        }

        $manager = AuthManager::getInstance();
        if ($manager->isGuest()) {
            throw new AuthenticationRequiredException('Authentication required');
        }
    }
}
