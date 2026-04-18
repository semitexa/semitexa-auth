<?php

declare(strict_types=1);

namespace Semitexa\Auth;

use Psr\Container\ContainerInterface;
use Semitexa\Auth\Context\AuthManager;
use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Auth\AuthBootstrapperFactoryInterface;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Container\RequestScopedContainer;
use Semitexa\Core\Discovery\ClassDiscovery;
use Semitexa\Core\Log\LoggerInterface;

/**
 * Builds a concrete AuthBootstrapper on demand.
 *
 * Registered in the DI container as the factory for AuthBootstrapperInterface so
 * Core's LifecycleComponentRegistry can construct the bootstrapper without ever
 * importing the concrete Semitexa\Auth\AuthBootstrapper class.
 */
#[SatisfiesServiceContract(of: AuthBootstrapperFactoryInterface::class)]
final class AuthBootstrapperFactory implements AuthBootstrapperFactoryInterface
{
    public function create(
        ContainerInterface $container,
        RequestScopedContainer $requestScopedContainer,
    ): AuthBootstrapperInterface {
        $classDiscovery = $container->has(ClassDiscovery::class)
            ? $container->get(ClassDiscovery::class)
            : null;

        $logger = $container->has(LoggerInterface::class)
            ? $container->get(LoggerInterface::class)
            : null;

        /**
         * AuthManager is the request-scoped facade over AuthContextStore. Passing it in
         * explicitly means the bootstrapper does not depend on static singleton access.
         */
        $authContext = $container->has(AuthContextInterface::class)
            ? $container->get(AuthContextInterface::class)
            : AuthManager::getInstance();

        /** @var ClassDiscovery|null $classDiscovery */
        /** @var LoggerInterface|null $logger */
        /** @var AuthContextInterface $authContext */
        return new AuthBootstrapper(
            container: $container,
            requestScopedContainer: $requestScopedContainer,
            classDiscovery: $classDiscovery,
            authContext: $authContext,
            logger: $logger,
        );
    }
}
