<?php
namespace Netlogix\OneClickSignOn\Security\Authentication\Token;

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
use TYPO3\Flow\Annotations as Flow;

/**
 * An authentication token used for sso credentials coming from typo3.org
 *
 * @Flow\Scope("prototype")
 */
class OneClickToken implements \TYPO3\Flow\Security\Authentication\TokenInterface {

	/**
	 * @var \TYPO3\Flow\Utility\Environment
	 */
	protected $environment;

	/**
	 * @var string
	 */
	protected $authenticationProviderName;

	/**
	 * Current authentication status of this token
	 * @var integer
	 */
	protected $authenticationStatus = self::NO_CREDENTIALS_GIVEN;

	/**
	 * The username/password credentials
	 * @var array
	 * @Flow\Transient
	 */
	protected $credentials = array('username' => '', 'signature' => '', 'expires' => '');

	/**
	 * @var \TYPO3\Flow\Security\Account
	 */
	protected $account;

	/**
	 * @var \TYPO3\Flow\Security\AccountRepository
	 */
	protected $accountRepository;

	/**
	 * @var array
	 */
	protected $requestPatterns = NULL;

	/**
	 * The authentication entry point
	 * @var \TYPO3\Flow\Security\Authentication\EntryPointInterface
	 */
	protected $entryPoint = NULL;

	/**
	 * @param \TYPO3\Flow\Utility\Environment $environment The current environment object
	 * @return void
	 * @author Robert Lemke <robert@typo3.org>
	 */
	public function injectEnvironment(\TYPO3\Flow\Utility\Environment $environment) {
		$this->environment = $environment;
	}

	/**
	 * @param \TYPO3\Flow\Security\AccountRepository $accountRepository
	 * @return void
	 * @author Robert Lemke <robert@typo3.org>
	 */
	public function injectAccountRepository(\TYPO3\Flow\Security\AccountRepository $accountRepository) {
		$this->accountRepository = $accountRepository;
	}

	/**
	 * Returns the name of the authentication provider responsible for this token
	 *
	 * @return string The authentication provider name
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getAuthenticationProviderName() {
		return $this->authenticationProviderName;
	}

	/**
	 * Sets the name of the authentication provider responsible for this token
	 *
	 * @param string $authenticationProviderName The authentication provider name
	 * @return void
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function setAuthenticationProviderName($authenticationProviderName) {
		$this->authenticationProviderName = $authenticationProviderName;
	}

	/**
	 * Returns TRUE if this token is currently authenticated
	 *
	 * @return boolean TRUE if this this token is currently authenticated
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function isAuthenticated() {
		return ($this->authenticationStatus === self::AUTHENTICATION_SUCCESSFUL);
	}

	/**
	 * Sets the authentication entry point
	 *
	 * @param \TYPO3\Flow\Security\Authentication\EntryPointInterface $entryPoint The authentication entry point
	 * @return void
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function setAuthenticationEntryPoint(\TYPO3\Flow\Security\Authentication\EntryPointInterface $entryPoint) {
		$this->entryPoint = $entryPoint;
	}

	/**
	 * Returns the configured authentication entry point, NULL if none is available
	 *
	 * @return \TYPO3\Flow\Security\Authentication\EntryPointInterface The configured authentication entry point, NULL if none is available
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getAuthenticationEntryPoint() {
		return $this->entryPoint;
	}

	/**
	 * Returns TRUE if \TYPO3\Flow\Security\RequestPattern were set
	 *
	 * @return boolean True if a \TYPO3\Flow\Security\RequestPatternInterface was set
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function hasRequestPatterns() {
		if ($this->requestPatterns != NULL) return TRUE;
		return FALSE;
	}

	/**
	 * Sets request patterns
	 *
	 * @param array $requestPatterns Array of \TYPO3\Flow\Security\RequestPattern to be set
	 * @return void
	 * @see hasRequestPattern()
	 */
	public function setRequestPatterns(array $requestPatterns) {
		$this->requestPatterns = $requestPatterns;
	}

	/**
	 * Returns an array of set \TYPO3\Flow\Security\RequestPatternInterface, NULL if none was set
	 *
	 * @return array Array of set request patterns
	 * @see hasRequestPattern()
	 */
	public function getRequestPatterns() {
		return $this->requestPatterns;
	}

	/**
	 * Updates the authentication credentials, the authentication manager needs to authenticate this token.
	 * This could be a username/password from a login controller.
	 * This method is called while initializing the security context. By returning TRUE you
	 * make sure that the authentication manager will (re-)authenticate the tokens with the current credentials.
	 * Note: You should not persist the credentials!
	 *
	 * @param \TYPO3\Flow\Mvc\ActionRequest $actionRequest The current request instance
	 * @return boolean TRUE if this token needs to be (re-)authenticated
	 */
	public function updateCredentials(\TYPO3\Flow\Mvc\ActionRequest $actionRequest) {
		$getArguments = $this->environment->getRawGetArguments();
		$username = \TYPO3\Flow\Reflection\ObjectAccess::getPropertyPath($getArguments, '__authentication.TYPO3.Flow.Security.Authentication.Token.OneClick.username');
		$signature = \TYPO3\Flow\Reflection\ObjectAccess::getPropertyPath($getArguments, '__authentication.TYPO3.Flow.Security.Authentication.Token.OneClick.signature');
		$expires = \TYPO3\Flow\Reflection\ObjectAccess::getPropertyPath($getArguments, '__authentication.TYPO3.Flow.Security.Authentication.Token.OneClick.expires');

		if (!empty($username) && !empty($signature) && !empty($expires)) {

			$this->credentials['username'] = $username;
			$this->credentials['signature'] = $signature;
			$this->credentials['expires'] = $expires;

			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
		}
	}

	/**
	 * Returns the credentials (username and password) of this token.
	 *
	 * @return object $credentials The needed credentials to authenticate this token
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getCredentials() {
		return $this->credentials;
	}

	/**
	 * Returns the account if one is authenticated, NULL otherwise.
	 *
	 * @return \TYPO3\Flow\Security\Account An account object
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getAccount() {
		return $this->account;
	}

	/**
	 * Set the (authenticated) account
	 *
	 * @param \TYPO3\Flow\Security\Account $account An account object
	 * @return void
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function setAccount(\TYPO3\Flow\Security\Account $account = NULL) {
		$this->account = $account;
	}

	/**
	 * Returns the currently valid roles.
	 *
	 * @return array Array of TYPO3\Flow\Security\Authentication\Role objects
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getRoles() {
		$account = $this->getAccount();
		return ($account !== NULL && $this->isAuthenticated()) ? $account->getRoles() : array();
	}

	/**
	 * Sets the authentication status. Usually called by the responsible \TYPO3\Flow\Security\Authentication\AuthenticationManagerInterface
	 *
	 * @param integer $authenticationStatus One of NO_CREDENTIALS_GIVEN, WRONG_CREDENTIALS, AUTHENTICATION_SUCCESSFUL, AUTHENTICATION_NEEDED
	 * @return void
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 * @throws \TYPO3\Flow\Security\Exception\InvalidAuthenticationStatusException
	 */
	public function setAuthenticationStatus($authenticationStatus) {
		if (!in_array($authenticationStatus, array(self::NO_CREDENTIALS_GIVEN, self::WRONG_CREDENTIALS, self::AUTHENTICATION_SUCCESSFUL, self::AUTHENTICATION_NEEDED))) {
			throw new \TYPO3\Flow\Security\Exception\InvalidAuthenticationStatusException('Invalid authentication status.', 1237224453);
		}
		$this->authenticationStatus = $authenticationStatus;
	}

	/**
	 * Returns the current authentication status
	 *
	 * @return integer One of NO_CREDENTIALS_GIVEN, WRONG_CREDENTIALS, AUTHENTICATION_SUCCESSFUL, AUTHENTICATION_NEEDED
	 * @author Andreas Förthner <andreas.foerthner@netlogix.de>
	 */
	public function getAuthenticationStatus() {
		return $this->authenticationStatus;
	}

	/**
	 * Returns a string representation of the token for logging purposes.
	 *
	 * @return string The username credential
	 * @author Christopher Hlubek <hlubek@networkteam.com>
	 */
	public function  __toString() {
		return 'Username: "' . $this->credentials['username'] . '"';
	}
}

?>