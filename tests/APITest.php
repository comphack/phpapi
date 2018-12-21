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
        //$api = new API($this->server, 'testuser');
        //$api->Register('testuser', 'testuser@test.test', 'testing');
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
        if($this->use_mock) {
          $this->assertEquals(1000000, $cp);
        }
    }

    public function assertTypeUser($ad) {
      $this->assertObjectHasAttribute('username', $ad);
      $this->assertObjectHasAttribute('displayName', $ad);
      $this->assertObjectHasAttribute('email', $ad);
      $this->assertObjectHasAttribute('ticketCount', $ad);
      $this->assertObjectHasAttribute('userLevel', $ad);
      $this->assertObjectHasAttribute('enabled', $ad);
      $this->assertObjectHasAttribute('lastLogin', $ad);

      $this->assertInternalType('string', $ad->username);
      $this->assertInternalType('string', $ad->displayName);
      $this->assertInternalType('string', $ad->email);
      $this->assertInternalType('int', $ad->ticketCount);
      $this->assertInternalType('int', $ad->userLevel);
      $this->assertInternalType('bool', $ad->enabled);
      $this->assertInternalType('int', $ad->lastLogin);
    }

    public function testAccountDetails() {
      $this->MockAuthenticate();
      $this->MockRequest('account/get_details', array(), array(
        'cp' => 1000000,
        'username' => 'testuser',
        'disp_name' => 'testuserdisplay',
        'email' => 'testing@test.test',
        'ticket_count' => 1,
        'user_level' => 1000,
        'enabled' => true,
        'last_login' => 0
      ));

      list($mock_http, $api) = $this->MockAPI();

      $ad = $api->GetAccountDetails();

      $this->assertObjectHasAttribute('cp', $ad);
      $this->assertInternalType('int', $ad->cp);
      $this->assertTypeUser($ad);

      if($this->use_mock) {
        $this->assertEquals(1000000, $ad->cp);
        $this->assertEquals('testuser', $ad->username);
        $this->assertEquals('testuserdisplay', $ad->displayName);
        $this->assertEquals('testing@test.test', $ad->email);
        $this->assertEquals(1, $ad->ticketCount);
        $this->assertEquals(1000, $ad->userLevel);
        $this->assertEquals(true, $ad->enabled);
        $this->assertEquals(0, $ad->lastLogin);
      }
    }

    public function testGetAccount() {
      $this->MockAuthenticate();
      $this->MockRequest('admin/get_account', array('username' => 'testuser'), array(
        'username' => 'testuser',
        'disp_name' => 'testuserdisplay',
        'email' => 'testing@test.test',
        'ticket_count' => 1,
        'user_level' => 1000,
        'enabled' => true,
        'last_login' => 0,
        'character_count' => 0
      ));

      list($mock_http, $api) = $this->MockAPI();

      $account = $api->GetAccount('testuser');

      $this->assertTypeUser($account);

      if($this->use_mock) {
        $this->assertEquals('testuser', $account->username);
        $this->assertEquals('testuserdisplay', $account->displayName);
        $this->assertEquals('testing@test.test', $account->email);
        $this->assertEquals(1, $account->ticketCount);
        $this->assertEquals(1000, $account->userLevel);
        $this->assertEquals(true, $account->enabled);
        $this->assertEquals(0, $account->lastLogin);
        $this->assertEquals(0, $account->characterCount);
      }
    }

    public function testGetAccounts() {
      $this->MockAuthenticate();
      $this->MockRequest('admin/get_accounts', array(), array('accounts' => array(array(
        'username' => 'testuser',
        'disp_name' => 'testuserdisplay',
        'email' => 'testing@test.test',
        'ticket_count' => 1,
        'user_level' => 1000,
        'enabled' => true,
        'last_login' => 0,
        'character_count' => 0
      ), array(
        'username' => 'testuser2',
        'disp_name' => 'testuser2display',
        'email' => 'testing@test.test',
        'ticket_count' => 1,
        'user_level' => 1000,
        'enabled' => true,
        'last_login' => 0,
        'character_count' => 0
      ))));

      list($mock_http, $api) = $this->MockAPI();
      $accounts = $api->GetAccounts();

      foreach($accounts as $account) {
        $this->assertTypeUser($account);
      }

      if($this->use_mock) {
        $this->assertEquals('testuser', $accounts[0]->username);
        $this->assertEquals('testuserdisplay', $accounts[0]->displayName);
        $this->assertEquals('testing@test.test', $accounts[0]->email);
        $this->assertEquals(1, $accounts[0]->ticketCount);
        $this->assertEquals(1000, $accounts[0]->userLevel);
        $this->assertEquals(true, $accounts[0]->enabled);
        $this->assertEquals(0, $accounts[0]->lastLogin);
        $this->assertEquals(0, $accounts[0]->characterCount);
      }
    }

    public function testDeleteAccount() {
      $this->MockAuthenticate();
      $this->MockRequest('admin/delete_account', array('username' => 'testuser'), array());

      list($mock_http, $api) = $this->MockAPI();
      $delete = $api->DeleteAccount('testuser');

      $this->assertEquals(true, $delete);
    }

    public function testUpdateAccount() {
      $this->MockAuthenticate();
      $this->MockRequest('admin/update_account', array(
        'username' => 'testuser',
        'cp' => 100000
      ), array(
        'error' => 'Success'
      ));

      list($mock_http, $api) = $this->MockAPI();
      $update = $api->UpdateAccount('testuser', array('cp' => 100000));

      $this->assertObjectHasAttribute('error', $update);
      $this->assertInternalType('string', $update->error);
      $this->assertEquals('Success', $update->error);
    }

    public function testChangePassword() {
      $this->MockAuthenticate();
      $this->MockRequest('account/change_password', array('password' => 'testing2'), array(
        'error' => 'Success'
      ));

      list($mock_http, $api) = $this->MockAPI();
      $changePw = $api->ChangePassword('testing2');

      $this->assertObjectHasAttribute('error', $changePw);
      $this->assertInternalType('string', $changePw->error);
      $this->assertEquals('Success', $changePw->error);
    }

    public function testCreateDeletePromo(): void
    {
        $startTime = new DateTime('NOW');
        $endTime = new DateTime('NOW');
        $endTime->add(new DateInterval('PT5M')); // 5 min

        $this->MockAuthenticate();
        $this->MockRequest('admin/create_promo', array(
            'code' => 'abc-123',
            'startTime' => $startTime->getTimestamp(),
            'endTime' => $endTime->getTimestamp(),
            'useLimit' => 0,
            'limitType' => 'account',
            'items' => array(1, 2, 3)
        ), array(
            'error' => 'Success'
        ));
        $this->MockRequest('admin/create_promo', array(
            'code' => 'abc-123',
            'startTime' => $startTime->getTimestamp(),
            'endTime' => $endTime->getTimestamp(),
            'useLimit' => 0,
            'limitType' => 'world',
            'items' => array(1, 2, 3)
        ), array(
            'error' => 'Promotion with that code already exists. Another will be made.'
        ));
        $this->MockRequest('admin/delete_promo', array(
            'code' => 'abc-123'
        ), array(
            'error' => 'Deleted 2 promotions.'
        ));

        list($mock_http, $api) = $this->MockAPI();

        $response = $api->CreatePromo('abc-123', $startTime, $endTime, 0,
            'account', array(1, 2, 3));

        $this->assertObjectHasAttribute('error', $response);
        $this->assertInternalType('string', $response->error);
        $this->assertEquals('Success', $response->error);

        $response = $api->CreatePromo('abc-123', $startTime, $endTime, 0,
            'world', array(1, 2, 3));

        $this->assertObjectHasAttribute('error', $response);
        $this->assertInternalType('string', $response->error);
        $this->assertEquals('Promotion with that code already exists. Another will be made.', $response->error);

        $response = $api->DeletePromo('abc-123');

        $this->assertObjectHasAttribute('error', $response);
        $this->assertInternalType('string', $response->error);
        $this->assertEquals('Deleted 2 promotions.', $response->error);
    }
}

?>
