<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for Ubersmith RWhois Server
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ubersmith extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(%rwhois)(.*?)(%ok)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^network:IP-Network-Block:(.+)$/im' => 'network:inetnum', 
                    '/^network:Network-Name:(.+)$/im' => 'network:name', 
                    '/^network:ID:(.+)$/im' => 'network:handle', 
                    '/^network:Class-Name:(.+)$/im' => 'status', 
                    '/^network:Created:(.+)$/im' => 'created', 
                    '/^network:Updated:(.+)$/im' => 'changed', 
                    '/^network:Org-Name:(.+)$/im' => 'contacts:owner:handle', 
                    '/^network:Org-Name:(.+)$/im' => 'contacts:owner:organization', 
                    '/^network:Street-Address:(.+)$/im' => 'contacts:owner:address', 
                    '/^network:City:(.+)$/im' => 'contacts:owner:city', 
                    '/^network:State:(.+)$/im' => 'contacts:owner:state', 
                    '/^network:Postal-Code:(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^network:Country-Code:(.+)$/im' => 'contacts:owner:country', 
                    '/^network:Tech-Contact:(.+)$/im' => 'contacts:tech:handle', 
                    '/^contact:Tech-Name:(.+)$/im' => 'contacts:tech:name', 
                    '/^contact:Tech-Phone:(.+)$/im' => 'contacts:tech:phone', 
                    '/^contact:Tech-Email:(.+)$/im' => 'contacts:tech:email', 
                    '/^contact:Abuse-Name:(.+)$/im' => 'contacts:abuse:handle', 
                    '/^contact:Abuse-Name:(.+)$/im' => 'contacts:abuse:name', 
                    '/^contact:Abuse-Phone:(.+)$/im' => 'contacts:abuse:phone', 
                    '/^contact:Abuse-Email:(.+)$/im' => 'contacts:abuse:email', 
                    '/^contact:POC-Name:(.+)$/im' => 'contacts:rtech:handle', 
                    '/^contact:POC-Name:(.+)$/im' => 'contacts:rtech:name', 
                    '/^contact:POC-Phone:(.+)$/im' => 'contacts:rtech:phone', 
                    '/^contact:POC-Email:(.+)$/im' => 'contacts:rtech:email', 
                    '/^ReferralServer:(.+)$/im' => 'referral_server'));

    /**
     * After parsing do something
     *
     * If ARNIC says the organization is different change the whois server and
     * restart parsing.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $Result = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        foreach ($Result->contacts as $contactType => $contactObject) {
            foreach ($contactObject as $contact) {
                if (isset($contact->handle) && $contact->handle === 'AFRINIC') {
                    $Result->reset();
                    $Config->setCurrent($Config->get('afrinic'));
                    $WhoisParser->call();
                }
            }
        }
        
        if (isset($Result->referral_server) && $Result->referral_server != '') {
            $referralServer = $Result->referral_server;
            $Result->reset();
            $mapping = $Config->get($referralServer);
            $template = str_replace('whois://', '', str_replace('rwhois://', '', $mapping['template']));
            $Config->setCurrent($Config->get($template));
            $WhoisParser->call();
        }
    }
}
