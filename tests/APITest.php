<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

use comp_hack\API;

final class APITest extends TestCase
{
    private static $seed;
    private static $faker;

    private $server;
    private $username;
    private $password;
    private $salt;
    private $challenge;
    private $requests;
    private $responses;
    private $use_mock;

    public static function setUpBeforeClass()
    {
        self::$faker = Faker\Factory::create();
        self::$seed = self::$faker->randomNumber;
        self::$faker->seed(self::$seed);

        print("Seed used for this test run: " . self::$seed . "\n\n");
    }

    public function setUp()
    {
        $this->server = 'http://127.0.0.1:10999/api/';
        $this->username = self::$faker->userName;
        $this->password = self::$faker->password;
        $this->salt = substr(self::$faker->md5, 0, 10);
        $this->challenge = substr(self::$faker->md5, 0, 10);
        $this->requests = array();
        $this->responses = array();
        $this->use_mock = true;

        // Uncomment these lines to test with a real server.
        //$this->username = 'omega';
        //$this->password = 'arbychicken';
        //$this->use_mock = false;
    }

    public function tearDown()
    {
    }

    //
    // Utility Functions
    //

    private function MockHttp()
    {
        if(!$this->use_mock)
        {
            return null;
        }

        $mock_http = $this->getMockBuilder(\GuzzleHttp\Client::class)
            ->setMethods(['post'])->getMocK();

        $chain = $mock_http->expects($this->exactly(
            count($this->requests)))->method('post');
        $chain = call_user_func_array(array($chain, 'withConsecutive'),
            $this->requests);
        $chain = call_user_func_array(array($chain,
            'willReturnOnConsecutiveCalls'), $this->responses);

        return $mock_http;
    }

    private function MockRequest($uri, $request, $response,
        $do_challenge = true)
    {
        if(!$this->use_mock)
        {
            return;
        }

        if($do_challenge)
        {
            $password_hash = hash('sha512', $this->password . $this->salt);
            $request['challenge'] = hash('sha512', $password_hash .
                $this->challenge);
            $this->challenge = substr(self::$faker->md5, 0, 10);
            $response['challenge'] = $this->challenge;
        }

        $mock_body = $this->getMockBuilder(
            \GuzzleHttp\Psr7\Stream::class)
            ->disableOriginalConstructor()
            ->setMethods(['getContents'])->getMocK();
        $mock_body->expects($this->once())->method(
            'getContents')->will($this->returnValue(json_encode($response)));

        $mock_response = $this->getMockBuilder(
            \GuzzleHttp\Psr7\Response::class)
            ->setMethods(['getStatusCode', 'hasHeader',
                'getHeader', 'getBody'])->getMock();
        $mock_response->expects($this->once())->method(
            'getStatusCode')->will($this->returnValue(200));
        $mock_response->expects($this->once())->method(
            'hasHeader')->with($this->equalTo('Content-Type'))->will(
                $this->returnValue(true));
        $mock_response->expects($this->once())->method(
            'getHeader')->with($this->equalTo('Content-Type'))->will(
                $this->returnValue(['application/json']));
        $mock_response->expects($this->once())->method(
            'getBody')->will($this->returnValue($mock_body));

        $this->requests[] = [$this->equalTo($uri), $this->equalTo(
            array('json' => $request))];
        $this->responses[] = $this->returnValue($mock_response);
    }

    private function MockAuthenticate()
    {
        if(!$this->use_mock)
        {
            return;
        }

        $request = array('username' => $this->username);
        $response = array(
            'salt' => $this->salt,
            'challenge' => $this->challenge
        );

        $this->MockRequest('auth/get_challenge',
            $request, $response, false);
    }

    private function MockError($uri, $request, $code = 403,
        $do_challenge = true)
    {
        if(!$this->use_mock)
        {
            return;
        }

        if($do_challenge)
        {
            $password_hash = hash('sha512', $this->password . $this->salt);
            $request['challenge'] = hash('sha512', $password_hash .
                $this->challenge);
            $this->challenge = substr(self::$faker->md5, 0, 10);
        }

        $mock_response = $this->getMockBuilder(
            \GuzzleHttp\Psr7\Response::class)
            ->setMethods(['getStatusCode'])->getMock();
        $mock_response->expects($this->once())->method(
            'getStatusCode')->will($this->returnValue($code));

        $this->requests[] = [$this->equalTo($uri), $this->equalTo(
            array('json' => $request))];
        $this->responses[] = $this->returnValue($mock_response);
    }

    private function MockAPI($authenticate = true)
    {
        $mock_http = $this->MockHttp();

        $api = new API($this->server, $this->username);

        if($this->use_mock)
        {
            $api->SetHttpClient($mock_http);
        }

        if($authenticate)
        {
            $this->assertTrue($api->Authenticate($this->password));
        }

        return [$mock_http, $api];
    }

    //
    // Tests
    //

    public function testGetters(): void
    {
        $api = new API($this->server, $this->username);
        $this->assertEquals($this->server, $api->GetServer());
        $this->assertEquals($this->username, $api->GetUsername());
    }

    public function testBadAuthenticate(): void
    {
        // Make sure these are bad even if we connect to a real server.
        $this->username = self::$faker->userName;
        $this->password = self::$faker->password;

        $this->MockError('auth/get_challenge', array(
            'username' => $this->username
        ), 403, false);

        list($mock_http, $api) = $this->MockAPI(false);
        $this->assertFalse($api->Authenticate($this->password));
    }

    public function testAuthenticate(): void
    {
        $this->MockAuthenticate();

        list($mock_http, $api) = $this->MockAPI();
    }

    public function testBadMethod(): void
    {
        $request = array('something' => self::$faker->text);

        $this->MockAuthenticate();
        $this->MockError('account/bad_method', $request);

        list($mock_http, $api) = $this->MockAPI();
        $this->assertFalse($api->Request('account/bad_method', $request));
    }

    public function testCP(): void
    {
        $this->MockAuthenticate();
        $this->MockRequest('account/get_cp', array(), array(
            'cp' => 1000000
        ));

        list($mock_http, $api) = $this->MockAPI();

        $cp = $api->GetCP();
        $this->assertInternalType('int', $cp);
        $this->assertEquals(1000000, $cp);
    }
}

?>
