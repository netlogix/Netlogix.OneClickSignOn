<?php
namespace Netlogix\OneClickSignOn\ViewHelpers\Uri;

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
 * A view helper for creating URIs to actions.
 *
 * = Examples =
 *
 * <code title="Defaults">
 * <f:uri.action>some link</f:uri.action>
 * </code>
 * <output>
 * currentpackage/currentcontroller
 * (depending on routing setup and current package/controller/action)
 * </output>
 *
 * <code title="Additional arguments">
 * <f:uri.action action="myAction" controller="MyController" package="YourCompanyName.MyPackage" subpackage="YourCompanyName.MySubpackage" arguments="{key1: 'value1', key2: 'value2'}">some link</f:uri.action>
 * </code>
 * <output>
 * mypackage/mycontroller/mysubpackage/myaction?key1=value1&amp;key2=value2
 * (depending on routing setup)
 * </output>
 *
 * @license http://www.gnu.org/licenses/lgpl.html GNU Lesser General Public License, version 3 or later
 * @api
 * @FLOW3\Scope("prototype")
 */
class ActionViewHelper extends \TYPO3\Fluid\ViewHelpers\Uri\ActionViewHelper {

	/**
	 * @var \TYPO3\FLOW3\Security\Cryptography\HashService
	 * @FLOW3\Inject
	 */
	protected $hashService;

	/**
	 * Render the Uri.
	 *
	 * @param string $action Target action
	 * @param array $arguments Arguments
	 * @param string $controller Target controller. If NULL current controllerName is used
	 * @param string $package Target package. if NULL current package is used
	 * @param string $subpackage Target subpackage. if NULL current subpackage is used
	 * @param string $section The anchor to be added to the URI
	 * @param string $format The requested format, e.g. ".html"
	 * @param array $additionalParams additional query parameters that won't be prefixed like $arguments (overrule $arguments)
	 * @param boolean $absolute If set, an absolute URI is rendered
	 * @param boolean $addQueryString If set, the current query parameters will be kept in the URI
	 * @param array $argumentsToBeExcludedFromQueryString arguments to be removed from the URI. Only active if $addQueryString = TRUE
	 * @param string $expires The expiration time of the generated link. The format must be compatible with strtotime. Default is 5 days ahead.
	 * @param string $username The account username to be logged in through this link
	 * @return string The rendered link
	 * @author Sebastian Kurfürst <sebastian@typo3.org>
	 * @author Bastian Waidelich <bastian@typo3.org>
	 * @api
	 */
	public function render($action = NULL, array $arguments = array(), $controller = NULL, $package = NULL, $subpackage = NULL, $section = '', $format = '',   array $additionalParams = array(), $absolute = TRUE, $addQueryString = FALSE, array $argumentsToBeExcludedFromQueryString = array(), $expires = NULL, $username = NULL) {

		if ($username !== NULL) {
			if ($expires === NULL)
				$expires = '+5 days';
			$expiresTimeStamp = strtotime($expires);
			$additionalParams['__authentication'] = array(
				'TYPO3' => array(
					'FLOW3' => array (
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

		$uriBuilder = $this->controllerContext->getUriBuilder();
		$uri = $uriBuilder
			->reset()
			->setSection($section)
			->setCreateAbsoluteUri($absolute)
			->setArguments($additionalParams)
			->setAddQueryString($addQueryString)
			->setArgumentsToBeExcludedFromQueryString($argumentsToBeExcludedFromQueryString)
			->setFormat($format)
			->uriFor($action, $arguments, $controller, $package, $subpackage);

		return $uri;
	}
}

?>