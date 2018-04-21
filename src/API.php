<?php declare(strict_types=1); namespace comp_hack;

class API
{
    private $http;
    private $server;
    private $username;
    private $salt;
    private $challenge;
    private $password_hash;

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

            return $response;
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

    public function Register($username, $email, $password)
    {
        try
        {
            $request = array();
            $request['username'] = $username;
            $request['email'] = $email;
            $request['password'] = $password;

            $uri = $this->server . "/account/register";
            $response = \Httpful\Request::post($uri)->sendsJson(
                )->expectsJson()->body($request)->send();

            if($response->hasErrors())
            {
                return false;
            }

            return $response->body->error;
        }
        catch(Exception $e)
        {
            return false;
        }
    } // function Register
} // class Session

?>
