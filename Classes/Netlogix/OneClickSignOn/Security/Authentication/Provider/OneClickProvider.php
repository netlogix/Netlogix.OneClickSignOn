<?php
namespace Netlogix\OneClickSignOn\Security\Authentication\Provider;

/*                                                                        *
 * This script belongs to the FLOW3 package "Netlogix.OneClickSignOn".    *
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU Lesser General Public License, either version 3   *
 * of the License, or (at your option) any later version.                 *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use Doctrine\ORM\Mapping as ORM;
use TYPO3\FLOW3\Annotations as FLOW3;

/**
 * An authentication provider that authenticates SSO requests from typo3.org
 *
 * @FLOW3\Scope("prototype")
 */
class OneClickProvider implements \TYPO3\FLOW3\Security\Authentication\AuthenticationProviderInterface {

	/**
	 * @var \TYPO3\FLOW3\Security\AccountRepository
	 * @FLOW3\Inject
	 */
	protected $accountRepository;

	/**
	 * @var \TYPO3\FLOW3\Security\Cryptography\HashService
	 * @FLOW3\Inject
	 */
	protected $hashService;

	/**
	 * @var string
	 */
	protected $name;

	/**
	 * @var array
	 */
	protected $options = array();

	/**
	 * Constructor
	 *
	 * @param string $name The name of this authentication provider
	 * @param array $options Additional configuration options
	 * @return void
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function __construct($name, array $options) {
		$this->name = $name;
		$this->options = $options;
	}

	/**
	 * Returns TRUE if the given token can be authenticated by this provider
	 *
	 * @param \TYPO3\FLOW3\Security\Authentication\TokenInterface $authenticationToken The token that should be authenticated
	 * @return boolean TRUE if the given token class can be authenticated by this provider
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function canAuthenticate(\TYPO3\FLOW3\Security\Authentication\TokenInterface $authenticationToken) {
		if ($authenticationToken->getAuthenticationProviderName() === $this->name) return TRUE;
		return FALSE;
	}

	/**
	 * Returns the classnames of the tokens this provider is responsible for.
	 *
	 * @return string The classname of the token this provider is responsible for
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getTokenClassNames() {
		return array('Netlogix\OneClickSignOn\Security\Authentication\Token\OneClickToken');
	}

	/**
	 * Sets isAuthenticated to TRUE for all tokens.
	 *
	 * @param \TYPO3\FLOW3\Security\Authentication\TokenInterface $authenticationToken The token to be authenticated
	 * @return void
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function authenticate(\TYPO3\FLOW3\Security\Authentication\TokenInterface $authenticationToken) {
		if (!($authenticationToken instanceof \Netlogix\OneClickSignOn\Security\Authentication\Token\OneClickToken)) {
			throw new \TYPO3\FLOW3\Security\Exception\UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
		}

		$account = NULL;
		$credentials = $authenticationToken->getCredentials();

		if (is_array($credentials) && isset($credentials['username'])) {
			$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->options['useProviderName']);
		}

		if (is_object($account)) {

			if ($this->hashService->validateHmac($credentials['username'].$credentials['expires'], $credentials['signature'])
				&& $credentials['expires'] > time()) {
				$authenticationToken->setAuthenticationStatus(\TYPO3\FLOW3\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL);
				$authenticationToken->setAccount($account);
			} else {
				$authenticationToken->setAuthenticationStatus(\TYPO3\FLOW3\Security\Authentication\TokenInterface::WRONG_CREDENTIALS);
			}

		} elseif ($authenticationToken->getAuthenticationStatus() !== \TYPO3\FLOW3\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL) {
			$authenticationToken->setAuthenticationStatus(\TYPO3\FLOW3\Security\Authentication\TokenInterface::NO_CREDENTIALS_GIVEN);
		}
	}
}

?>
