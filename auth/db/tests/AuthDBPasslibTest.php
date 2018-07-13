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

namespace auth\db\tests;

/**
 * Tets passlib crypt handlers methods.
 * Does not require any special test environment.
 *
 *     [@moodle_root/auth/db/]$ phpunit tests/AuthDBPasslibTest.php
 *     OK (8 tests, 14 assertions)
 *
 * @package    auth_db
 * @category   phpunit
 * @copyright  2018 Paweł Suwiński
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class AuthDBPasslibTest extends \PHPUnit_Framework_TestCase {

    /*
     * Fixtures
     * @see https://passlib.readthedocs.io/en/stable/lib/passlib.hash.atlassian_pbkdf2_sha1.html
     */
    const HANDLER  = 'atlassian_pbkdf2_sha1';
    const PASSWORD  = 'password';
    const HASH  = '{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J';

    protected static $methods = array(
        'python_exec',
        'passlib_verify',
        'passlib_list_crypt_handlers',

    );

    protected static $pathtopython = null;
    protected static $passlibinstalled = false;

    protected static $debugecho = true;
    protected static $debugmessages = array();

    protected $authdb;

    /*
     * debugging
     *
     * helper stub of moodle method
     *
     * @param string $msg
     * @return void
     */
    public static function debugging($msg) {
        self::$debugmessages[] = $msg;
        if (self::$debugecho) {
            echo $msg."\n";
        }
    }

    public static function setUpBeforeClass() {

        self::$pathtopython = getenv('PYTHONBIN')
            ? getenv('PYTHONBIN')
            : self::findPython();
        if (!is_null(self::$pathtopython)) {
            self::$passlibinstalled =
                self::cmd_exec(self::$pathtopython, 'import passlib') !== false;
        }

        self::initClasses();
    }

    public function setUp() {
        global $CFG;

        if (is_null(self::$pathtopython)) {
            $this->markTestSkipped(
                'Python not found! Set PYTHONBIN env variable if installed.'
            );
        }
        if (!self::$passlibinstalled) {
            $this->markTestSkipped(
                'Passlib python module not istalled!'
            );
        }

        if (!is_object($CFG)) {
            $CFG = new \stdClass();
        }
        if (empty($CFG->pathtopython)) {
            $CFG->pathtopython = self::$pathtopython;
        }

        $this->authdb = new auth_plugin_db();
        $this->authdb->config = new \stdClass();
        $this->authdb->config->passtype = 'passlib:'.self::HANDLER;

        self::$debugecho = true;
    }

    public function testPathToPythonNotSetException() {
        $GLOBALS['CFG']->pathtopython = null;
        $this->assertMoodleException(
            'import passlib',
            'auth_db:pathtopythonnotset'
        );
    }

    public function testPythonExecErrorException() {
        self::$debugmessages = array();
        self::$debugecho = false;
        $this->assertCount(0, self::$debugmessages);

        $this->assertMoodleException(
            'import',
            'auth_db:pythonexecerror'
        );

        $this->assertCount(1, self::$debugmessages);
        $this->assertRegexp('/SyntaxError/', end(self::$debugmessages));
    }

    protected function assertMoodleException($cmd, $msg = null) {
        $e = null;
        try {
            auth_plugin_db::python_exec($cmd);
        } catch(\Exception $e) {
        }
        $this->assertInstanceOf(moodle_exception::class, $e);
        if($msg !== null) {
            $this->assertEquals($msg, $e->getMessage());
        }
    }

    public function testPaslibCryptHandlersListNotEmpty() {
        $handlers = auth_plugin_db::passlib_list_crypt_handlers();
        $this->assertInternalType('array', $handlers);
        $this->assertNotEmpty($handlers);
    }

    /*
     * @depends testPaslibCryptHandlersListNotEmpty
     */
    public function testJiraHandlerAvaible() {
        $this->assertContains(
            self::HANDLER,
            auth_plugin_db::passlib_list_crypt_handlers(),
            'Jira crypt handler not avaible!'
        );
    }

    /*
     * @depends testJiraHandlerAvaible
     */
    public function testPasswordValid() {
        $this->assertTrue($this->authdb->passlib_verify(
            self::PASSWORD,
            self::HASH
        ));
    }

    /**
     * testPasswordEscaping
     *
     * any special characters shouldn't brake python code
     *
     * @depends testJiraHandlerAvaible
     * @dataProvider providerPasswordEscaping
     * @param string $suffix
     * @return void
     */
    public function testPasswordEscaping($suffix) {
        $this->assertFalse($this->authdb->passlib_verify(
            self::PASSWORD.$suffix,
            self::HASH.$suffix
        ));
    }

    /**
     * @return array
     */
    public function providerPasswordEscaping() {
        return [["'"], ['"'], ['\\']];
    }


    /**
     * initClasses
     *
     * Parses auth.php file looking for passlib crypt handlers methods and
     * creates stubs of auth_plugin_db class containing these methods and
     * required dependends in tests namespace.
     *
     * @return void
     */
    protected static function initClasses() {
        if (!class_exists('auth_plugin_db')) {
            $isPasslibMethod = function ($line) {
                return preg_match('/\bfunction ('.implode('|', self::$methods).')\(/', $line);
            };
            $fb = fopen(__DIR__.'/../auth.php', 'r');
            $start = false;
            $code = null;
            while ($line = fgets($fb, 4096)) {
                if($start && preg_match('/\bfunction /', $line)
                         && !$isPasslibMethod($line)) {
                    break;
                }
                if(!$start && $isPasslibMethod($line)) {
                    $start = true;
                }
                if($start) {
                    $code .= $line;
                }
            }
            fclose($fb);
            if (empty($code)) {
                throw new \LogicException('Passlib methods code not found!');
            }
            eval(<<<EOT
namespace auth\\db\\tests;

class auth_plugin_db {
    public \$config;
    $code
}
EOT
            );
        }
        foreach (self::$methods as $method) {
            if (!is_callable(auth_plugin_db::class.'::'.$method)) {
                throw new \LogicException(sprintf(
                    'auth.php parser error: method "%s" not defined!',
                    $method
                ));
            }
        }

        if (!class_exists('moodle_exception')) {
            eval(<<<EOT
namespace auth\\db\\tests;

class moodle_exception extends \Exception {
    public function __construct(\$msg, \$ns) {
        parent::__construct(\$ns.':'.\$msg);
    }
}
EOT
            );
        }

        if (!function_exists(__NAMESPACE__.'\debugging')) {
            function debugging($msg) {
                AuthDBPasslibTest::debugging($msg);
            }
        }
    }

    /**
     * findPython
     *
     * Looks for python path on the server. Return null if not found.
     *
     * @return string
     */
    protected static function findPython() {
        $cmd = strtolower(substr(PHP_OS, 0, 3)) === 'win' ? 'where' : 'which';
        foreach (['python', 'python3', 'python2'] as $name) {
            $pathtopython = self::cmd_exec($cmd.' '.$name);
            if (!empty($pathtopython)) {
                return $pathtopython;
            }
        }
        return null;
    }

    /**
     * shell_exec version with stdin pipe
     *
     * @param string $cmd shell command to execute
     * @param string $stdin strinig to write to command stdin
     * @return mixed false on error and command stdout as string on success
     */
    protected static function cmd_exec($cmd, $stdin = null) {
        $proc = proc_open(
            $cmd,
            [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
            $pipes
        );
        if (!is_resource($proc)) {
            throw new \RuntimeException(
                sprintf('Unable to run command "%s"!', $cmd)
            );
        }
        if (!is_null($stdin)) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        return proc_close($proc) !== 0 ? false : trim($stdout);
    }

}
