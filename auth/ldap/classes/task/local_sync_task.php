<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace auth_ldap\task;
defined('MOODLE_INTERNAL') || die();

/**
 * A scheduled task for LDAP sync exisiting local users.
 *
 * @package    auth_ldap
 * @author     Paweł Suwiński <psuw@wp.pl>
 * @copyright  2020 Paweł Suwiński
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class local_sync_task extends \core\task\scheduled_task {

    /*
     * print info about every account processed 
     */ 
    public static $verbose = false;
    
    protected $ldapauth = null;
    protected $counters = array(); 

    /*
     * __call
     *
     * Workaround for calling auth_plugin_ldap protected methods to not 
     * to touch the class itself, same package so it is accepted. 
     *
     * @param string $name
     * @param array $args
     */
    public function __call($name, array $args) {
        if(in_array($name, array('get_profile_keys', 'update_user_record',
                'is_user_suspended'))) {
            $method  = new \ReflectionMethod($this->ldapauth, $name);
            $method->setAccessible(true);
            return $method->invoke($this->ldapauth, ...$args);
        }
        if(method_exists(get_parent_class($this), '__call')) {
            return parent::__call($name, $args);
        }
        throw new \BadMethodCallException(__CLASS__.'::'.$name);
    }

    /**
     * @inheritdoc
     */
    public function get_name() {
        return get_string('localsynctask', 'auth_ldap');
    }

    /**
     * Run local users LDAP sync sync.
     */
    public function execute() {
        global $CFG, $DB;

        require_once($CFG->dirroot.'/user/lib.php');
        if (!is_enabled_auth('ldap')) {
            return;
        }

        $this->counters = array_fill_keys(array('skipped', 'updated', 'removed', 'suspended'), 0);

        $this->ldapauth = get_auth_plugin('ldap');
        $this->ldapauth->ldap_connect(); 

        $select = array(
            'deleted <> 1',
            'id <> :guestid',
            'mnethostid = :mnethostid',
            'auth = :auth',
        );
        if(!$this->ldapauth->config->sync_suspended) {
            $select[] = 'suspended <> 1';
        }
        $users = $DB->get_recordset_select(
            'user', 
            implode(' AND ', $select),
            array(
                'guestid'     => $CFG->siteguest,
                'mnethostid'  => $CFG->mnet_localhost_id,
                'auth'        => $this->ldapauth->authtype,
            ),
            'username ASC',
            'id, username, suspended' 
        );

        mtrace('LDAP syncing existing local users...');

        $transaction = $DB->start_delegated_transaction();
        $updatekeys = $this->get_profile_keys();
        foreach($users as $user) {
            if(self::$verbose) {
                mtrace(sprintf('--> %s (%s): ', $user->username, $user->id), '');
            }
            if($userinfo = $this->ldapauth->get_userinfo($user->username)) {
                $isUserSuspended = $this->is_user_suspended((object)$userinfo);
                if(!empty($updatekeys) 
                        && $this->update_user_record($user->username, $updatekeys, true, $isUserSuspended)) {
                    $this->updateCounter($isUserSuspended ? 'suspended' : 'updated');
                /// Revive suspended - user not updated
                } else if($isUserSuspended != $user->suspended) {
                    user_update_user((object) ['id' => $user->id, 'suspended' => (int)$isUserSuspended], false);
                    $this->updateCounter($isUserSuspended ? 'suspended' : 'updated');
                } else {
                    $this->updateCounter('skipped');
                }
                $this->ldapauth->sync_roles($user);
            // user does not exist in LDAP so it should be removed or suspended
            } else if ($this->ldapauth->config->removeuser == AUTH_REMOVEUSER_FULLDELETE) {
                if (delete_user($user)) {
                    $this->updateCounter('removed');
                } else {
                    mtrace('error deleting user');
                }
            } else if ($this->ldapauth->config->removeuser == AUTH_REMOVEUSER_SUSPEND
                    && $user->suspended == 0) {
                user_update_user((object) ['id' => $user->id, 'suspended' => 1], false);
                \core\session\manager::kill_user_sessions($user->id);
                $this->updateCounter('suspended');
            } else {
                $this->updateCounter('skipped');
            }
        }
        $transaction->allow_commit();
        mtrace('');
        foreach ($this->counters as $key => $val) {
            mtrace("$key: $val");
        }
        mtrace('');
        mtrace('total: '.array_sum($this->counters));
        mtrace('');
        $this->ldapauth->ldap_close();
    }
    private function updateCounter($counter) { 
        $this->counters[$counter]++;
        if(self::$verbose) {
            mtrace($counter);
        }
    }
    
}
