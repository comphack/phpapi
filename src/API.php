<?php declare(strict_types=1); namespace comp_hack;

class API
{
    protected $http;
    protected $server;
    protected $username;
    protected $salt;
    protected $password_hash;
    protected $challenge;

    public function __construct($server, $username)
    {
        if(substr($server, -1) != '/')
        {
            $server = $server . '/';
        }

        $this->http = new \GuzzleHttp\Client(['base_uri' => $server]);

        $this->server = $server;
        $this->username = $username;
    } // function __construct

    public function GetServer(): string
    {
        return $this->server;
    } // function GetServer

    public function GetUsername(): string
    {
        return $this->username;
    } // function GetUsername

    public function GetPasswordHash(): string
    {
        return $this->password_hash;
    } // function GetPasswordHash

    public function SetHttpClient($http)
    {
        $this->http = $http;
    } // function SetHttpClient

    public function Authenticate($password): bool
    {
        try
        {
            $request = array('username' => $this->username);
            $response = $this->http->post('auth/get_challenge',
                ['json' => $request]);

            if(200 != $response->getStatusCode() ||
                !$response->hasHeader('Content-Type') ||
                'application/json' != $response->getheader('Content-Type')[0])
            {
                return false;
            }

            $response = json_decode($response->getBody()->getContents());

            if(!$response || !is_object($response) ||
                !property_exists($response, 'salt') ||
                !property_exists($response, 'challenge'))
            {
                return false;
            }

            $this->salt = $response->salt;
            $this->password_hash = hash('sha512',
                $password . $this->salt);
            $this->challenge = hash('sha512', $this->password_hash .
                $response->challenge);

            $this->SaveSession();
        }
        catch(\GuzzleHttp\Exception\ConnectException $e)
        {
            return false;
        }
        catch(\GuzzleHttp\Exception\ClientException $e)
        {
            return false;
        }
        catch(Exception $e)
        {
            return false;
        }

        return true;
    } // function Authenticate

    public function Request($api_method, $request = array())
    {
        try
        {
            if(substr($api_method, 0, 1) == '/')
            {
                $api_method = substr($api_method, 1);
            }

            $request['challenge'] = $this->challenge;
            $response = $this->http->post($api_method,
                ['json' => $request]);

            if(200 != $response->getStatusCode() ||
                !$response->hasHeader('Content-Type') ||
                'application/json' != $response->getheader('Content-Type')[0])
            {
                return false;
            }

            $response = json_decode($response->getBody()->getContents());

            if(!$response || !is_object($response) ||
                !property_exists($response, 'challenge'))
            {
                return false;
            }

            $this->challenge = hash('sha512', $this->password_hash .
                $response->challenge);

            $this->SaveSession();

            return $response;
        }
        catch(\GuzzleHttp\Exception\ConnectException $e)
        {
            return false;
        }
        catch(\GuzzleHttp\Exception\ClientException $e)
        {
            return false;
        }
        catch(Exception $e)
        {
            return false;
        }
    } // function Request

    public function GetCP()
    {
        $response = $this->Request('account/get_cp');

        if(false === $response || !property_exists($response, 'cp'))
        {
            return false;
        }

        return $response->cp;
    }

    public function GetAccountDetails()
    {
        $response = $this->Request('account/get_details');

        if(false === $response ||
            !property_exists($response, 'cp') ||
            !property_exists($response, 'username') ||
            !property_exists($response, 'disp_name') ||
            !property_exists($response, 'email') ||
            !property_exists($response, 'ticket_count') ||
            !property_exists($response, 'user_level') ||
            !property_exists($response, 'enabled') ||
            !property_exists($response, 'last_login'))
        {
            return false;
        }

        $object = new \stdClass();
        $object->username = $response->username;
        $object->displayName = $response->disp_name;
        $object->email = $response->email;
        $object->ticketCount = (int)$response->ticket_count;
        $object->userLevel = $response->user_level;
        $object->enabled = (bool)$response->enabled;
        /// @todo Convert this to a Carbon object?
        $object->lastLogin = (int)$response->last_login;

        return $object;
    }

    public function GetWebAuthLogin($clientVersion)
    {
        $response = $this->Request('account/client_login', array(
            'client_version' => $clientVersion
        ));

        if(false === $response ||
            !property_exists($response, 'error') ||
            !property_exists($response, 'error_code'))
        {
            return false;
        }

        $object = new \stdClass();
        $object->error = $response->error;
        $object->errorCode = $response->error_code;

        if(property_exists($response, 'sid1') &&
            property_exists($response, 'sid2'))
        {
            $object->sid1 = $response->sid1;
            $object->sid2 = $response->sid2;
        }

        return $object;
    }

    public function Register($username, $email, $password)
    {
        try
        {
            $request = array();
            $request['username'] = $username;
            $request['email'] = $email;
            $request['password'] = $password;

            $response = $this->http->post('account/register',
                ['json' => $request]);

            if(200 != $response->getStatusCode() ||
                !$response->hasHeader('Content-Type') ||
                'application/json' != $response->getheader('Content-Type')[0])
            {
                return false;
            }

            $response = json_decode($response->getBody()->getContents());

            if(!$response || !is_object($response) ||
                !property_exists($response, 'error'))
            {
                return false;
            }

            return $response->error;
        }
        catch(\GuzzleHttp\Exception\ConnectException $e)
        {
            return false;
        }
        catch(\GuzzleHttp\Exception\ClientException $e)
        {
            return false;
        }
        catch(Exception $e)
        {
            return false;
        }
    } // function Register

    protected function SaveSession()
    {
        // Extend this class and implement if you need a session.
    } // function SaveSession
} // class Session
