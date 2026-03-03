<?php

declare(strict_types=1);

namespace Semitexa\Auth\Pipeline;

use Semitexa\Auth\AuthBootstrapper;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Core\Attributes\AsPipelineListener;
use Semitexa\Core\Attributes\RequiresAuth;
use Semitexa\Core\Contract\PayloadInterface;
use Semitexa\Core\Pipeline\AuthCheck;
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
    public function handle(RequestPipelineContext $context): void
    {
        $authBootstrapper = $context->authBootstrapper instanceof AuthBootstrapper ? $context->authBootstrapper : null;

        if ($authBootstrapper === null || !$authBootstrapper->isEnabled()) {
            $this->checkRequiresAuth($context);
            return;
        }

        if ($context->requestDto instanceof PayloadInterface) {
            $authBootstrapper->handle($context->requestDto);
        }

        $context->authResult = AuthManager::getInstance()->getLastResult();

        $this->checkRequiresAuth($context);
    }

    private function checkRequiresAuth(RequestPipelineContext $context): void
    {
        $ref = new \ReflectionClass($context->requestDto);
        if ($ref->getAttributes(RequiresAuth::class) === []) {
            return;
        }

        if (AuthManager::getInstance()->isGuest()) {
            throw new AuthenticationRequiredException('Authentication required');
        }
    }
}
