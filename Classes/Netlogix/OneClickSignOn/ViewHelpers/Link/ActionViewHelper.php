<?php
namespace Netlogix\OneClickSignOn\ViewHelpers\Link;

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
 * A view helper for creating links to actions.
 *
 * = Examples =
 *
 * <code title="Defaults">
 * <f:link.action>some link</f:link.action>
 * </code>
 * <output>
 * <a href="currentpackage/currentcontroller">some link</a>
 * (depending on routing setup and current package/controller/action)
 * </output>
 *
 * <code title="Additional arguments">
 * <f:link.action action="myAction" controller="MyController" package="YourCompanyName.MyPackage" subpackage="YourCompanyName.MySubpackage" arguments="{key1: 'value1', key2: 'value2'}">some link</f:link.action>
 * </code>
 * <output>
 * <a href="mypackage/mycontroller/mysubpackage/myaction?key1=value1&amp;key2=value2">some link</a>
 * (depending on routing setup)
 * </output>
 *
 * @license http://www.gnu.org/licenses/lgpl.html GNU Lesser General Public License, version 3 or later
 * @api
 * @Flow\Scope("prototype")
 */
class ActionViewHelper extends \TYPO3\Fluid\ViewHelpers\Link\ActionViewHelper {

	/**
	 * @var \TYPO3\Flow\Security\Cryptography\HashService
	 * @Flow\Inject
	 */
	protected $hashService;

	/**
	 * Initialize arguments
	 *
	 * @return void
	 * @author Bastian Waidelich <bastian@typo3.org>
	 * @api
	 */
	public function initializeArguments() {
		parent::initializeArguments();
//		$this->registerTagAttribute('expires', 'string', 'The expiration time of the generated link. The format must be compatible with strtotime. Default is 5 days ahead');
	}

	/**
	 * Render the link.
	 *
	 * @param string $action Target action
	 * @param array $arguments Arguments
	 * @param string $controller Target controller. If NULL current controllerName is used
	 * @param string $package Target package. if NULL current package is used
	 * @param string $subpackage Target subpackage. if NULL current subpackage is used
	 * @param string $section The anchor to be added to the URI
	 * @param string $format The requested format, e.g. ".html"
	 * @param array $additionalParams additional query parameters that won't be prefixed like $arguments (overrule $arguments)
	 * @param boolean $addQueryString If set, the current query parameters will be kept in the URI
	 * @param array $argumentsToBeExcludedFromQueryString arguments to be removed from the URI. Only active if $addQueryString = TRUE
	 * @param string $expires The expiration time of the generated link. The format must be compatible with strtotime. Default is 5 days ahead.
	 * @param string $username The account username to be logged in through this link
	 * @return string The rendered link
	 * @author Sebastian Kurfürst <sebastian@typo3.org>
	 * @author Bastian Waidelich <bastian@typo3.org>
	 * @api
	 */
	public function render($action = NULL, $arguments = array(), $controller = NULL, $package = NULL, $subpackage = NULL, $section = '', $format = '',  array $additionalParams = array(), $addQueryString = FALSE, array $argumentsToBeExcludedFromQueryString = array(), $expires = NULL, $username = NULL) {

		if ($username !== NULL) {
			if ($expires === NULL)
				$expires = '+5 days';
			$expiresTimeStamp = strtotime($expires);
			$additionalParams['__authentication'] = array(
				'TYPO3' => array(
					'Flow' => array (
						'Security' => array(
							'Authentication' => array(
								'Token' => array(
									'OneClick' => array(
										'expires' => $expiresTimeStamp,
										'username' => $username,
										'signature' => $this->hashService->generateHmac($username.$expiresTimeStamp)
									)
								)
							)
						)
					)
				)
			);
		}

		return parent::render($action, $arguments, $controller, $package, $subpackage, $section, $format,  $additionalParams, $addQueryString, $argumentsToBeExcludedFromQueryString);

	}

}


?>
