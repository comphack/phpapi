<?php declare(strict_types=1); namespace comp_hack;

/*
|--------------------------------------------------------------------------
| COMPHACK PHP API
|--------------------------------------------------------------------------
| This is a full implementation of the API of the current release of the comp_hack server emulator.
| For this version of the API the current release is Kodama v2.2.1
| This should be extended inside your project and SaveSession should be overrided
| to save your session object.
*/

class API
{
    protected $http;
    protected $server;
    protected $username;
    protected $salt;
    protected $password_hash;
    protected $challenge;

    /**
     * Creates a new instance of this API, and sets the base information we need to start with.
     * Generally this should be followed with an Authenticate
     * @param string $server   The full url of the API server [EX: '127.0.0.1:10999/api']
     * @param string $username The username to be used to login to the API.
     */
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

    /**
     * Returns the address being used to access the API
     * @return string URL of the API server.
     */
    public function GetServer(): string
    {
        return $this->server;
    } // function GetServer

    /**
     * Returns the username of the current API user.
     * @return string The username of the current API user.
     */
    public function GetUsername(): string
    {
        return $this->username;
    } // function GetUsername

    /**
     * Gets the current password hash. Only available after it is constructed in Authenticate
     * @return string the password hash.
     */
    public function GetPasswordHash(): string
    {
        return $this->password_hash;
    } // function GetPasswordHash

    /**
     * A setter function to use a different http client. It's in the name.
     * @param object $http an object to be used to make API requests.
     */
    public function SetHttpClient($http)
    {
        $this->http = $http;
    } // function SetHttpClient

    /**
     * Authenticates the user specified during __construct.
     * Is required before accessing any endpoints other than auth/get_challenge and account/register
     * @param  string $password A password to be hashed and checked against the challenge.
     * @return bool             Whether or not the Authentication was successful.
     */
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

    /**
     * Helper function to make extending this API much easier.
     * Sends a POST request from the currently authenticated user to the enpoint specified.
     * This function should never need to be used outside of this file.
     *
     * @param string $api_method The URI of the api endpoint minus the '/api/' part
     * @param array  $request    A key=>value array of objects that will be converted to JSON and sent in the POST body.
     */
    public function Request($api_method, $request = array())
    {
        try
        {
            if(substr($api_method, 0, 1) == '/')
            {
                $api_method = substr($api_method, 1);
            }

            $request['session_username'] = $this->username;
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

    /**
     * Gets the CP of the currently authenticated account.
     */
    public function GetCP()
    {
        $response = $this->Request('account/get_cp');

        if(false === $response || !property_exists($response, 'cp'))
        {
            return false;
        }

        return $response->cp;
    }

    /**
     * Gets the details of the account currently Authenticated.
     *
     * This returns an account object containing fields:
     *  username string
     *  displayName string
     *  email string
     *  ticketCount int
     *  userLevel int
     *  enabled boolean
     *  lastlogin timestamp
     */
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

        /// @todo convert this to actual user class.
        $object = new \stdClass();
        $object->cp = $response->cp;
        $object->username = $response->username;
        $object->displayName = $response->disp_name;
        $object->email = $response->email;
        $object->ticketCount = (int)$response->ticket_count;
        $object->userLevel = (int)$response->user_level;
        $object->enabled = (bool)$response->enabled;
        /// @todo Convert this to a Carbon object?
        $object->lastLogin = (int)$response->last_login;

        return $object;
    }

    /**
     * Used by the client to login. Pointed to in the webaccess.sdat file.
     *
     * @param string $clientVersion  The client version string to check.
     * Must match the current servers client version variable.
     */
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

    /**
     * Registers a new user to the game server.
     * Does not require to be authenticated to use.
     *
     * @param string $username The username to log into the game server.
     * @param string $email    The email on record for the game server.
     * @param string $password The desired password.
     *
     * Users must be authenticated after registering in order to auto log-in.
     */
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

    /**
     * Allows you to request an account from the game server by username.
     * @param string $username The username of the account to be retrived
     */
    public function GetAccount($username) {
      $response = $this->Request('admin/get_account', array(
        'username' => $username
      ));

      if(false === $response ||
        !property_exists($response, 'cp') ||
        !property_exists($response, 'username') ||
        !property_exists($response, 'disp_name') ||
        !property_exists($response, 'email') ||
        !property_exists($response, 'ticket_count') ||
        !property_exists($response, 'user_level') ||
        !property_exists($response, 'enabled') ||
        !property_exists($response, 'last_login') ||
        !property_exists($response, 'character_count'))
      {
        return false;
      }

      $object = new \stdClass();
      $object->cp = $response->cp;
      $object->username = $response->username;
      $object->displayName = $response->disp_name;
      $object->email = $response->email;
      $object->ticketCount = (int)$response->ticket_count;
      $object->userLevel = $response->user_level;
      $object->enabled = (bool)$response->enabled;
      $object->lastLogin = (int)$response->last_login;
      $object->characterCount = (int)$response->character_count;

      return $object;
    }

    /**
     * Returns an array of user objects each object includes all details about the user besides their hash and salt.
     * Must be authenticated as an admin to use.
     */
    public function GetAccounts()
    {
      $response = $this->Request('admin/get_accounts');

      if(false === $response ||
        !property_exists($response, 'accounts'))
      {
        return false;
      }

      $accounts = array();

      foreach ($response->accounts as $account) {

        $object = new \stdClass();
        $object->cp = $account->cp;
        $object->username = $account->username;
        $object->displayName = $account->disp_name;
        $object->email = $account->email;
        $object->ticketCount = (int)$account->ticket_count;
        $object->userLevel = $account->user_level;
        $object->enabled = (bool)$account->enabled;
        $object->lastLogin = (int)$account->last_login;
        $object->characterCount = (int)$account->character_count;

        array_push($accounts, $object);
      }

      return $accounts;
    } //function GetAccounts

    /**
     * Delete's the account specified by username.
     * Must be authenticated as an admin to use.
     * @param string $username The Username of the account to be deleted.
     */
    public function DeleteAccount($username)
    {
      $response = $this->Request('admin/delete_account', array(
        'username' => $username
      ));

      if(false === $response) {
        return false;
      }

      return true;
    }//function DeleteAccount

    /**
     * [This will update any users account by changing their fields with values specified by the same key in $changeArray]
     * @param string $username    The Username of the account to be changed.]
     * @param array $changeArray  An array of keys and that match to at least one of the following list.
     * Valid $changeArray keys are:
     *  password  string | Changes Password.
     *  disp_name string | Changes display name.
     *  cp        int    | Changes CP Value.
     *  ticket_count int | changes amount of character tickets.
     *  user_level  int  | Sets the user level 0 is default 1000 is admin.
     *  enabled  boolean | Controls if the account can login to the game.
     */
    public function UpdateAccount($username, $changeArray)
    {
      $response = $this->Request('admin/update_account', array_merge($changeArray, array('username' => $username)));
      if(false === $response ||
        !is_object($response) ||
        !property_exists($response, 'error'))
      {
          return false;
      }
      return $response;
    }//function UpdateUser

    /**
     * Changes the password of the current user.
     * @param string $password the new password to be changed to.
     */
    public function ChangePassword($password)
    {
      $response = $this->Request('account/change_password', ['password' => $password]);

      if(false === $response ||
        !is_object($response) ||
        !property_exists($response, 'error'))
      {
        return false;
      }

      return $response;
    }//function ChangePassword

    /**
     * Gets a list of promotions.
     */
    public function GetPromos()
    {
        $response = $this->Request('admin/get_promos');

        if(false === $response ||
            !is_object($response) ||
            !property_exists($response, 'promos'))
        {
            return false;
        }

        return $response['promos'];
    } // function GetPromos

    /**
     * Creates a new promotion code that can be used to get items.
     * @param code Promotion code to use. This must be unique.
     * @param startTime Timestamp for the start of the promotion.
     * @param endTime Timestamp for the end of the promotion.
     * @param useLimit Number of times the promotion may be used.
     * @param limitType What type to limit by the use limit. Can be 'character',
     *   'world' or 'account'.
     * @param items List of shop product item IDs to give during the promotion.
     */
    public function CreatePromo(string $code, \DateTime $startTime,
        \DateTime $endTime, int $useLimit, string $limitType, array $items)
    {
        $response = $this->Request('admin/create_promo', [
            'code' => $code,
            'startTime' => $startTime->getTimestamp(),
            'endTime' => $endTime->getTimestamp(),
            'useLimit' => $useLimit,
            'limitType' => $limitType,
            'items' => $items
        ]);

        if(false === $response ||
            !is_object($response) ||
            !property_exists($response, 'error'))
        {
            return false;
        }

        return $response;
    } // function CreatePromo

    /**
     * Deletes all promotions with the given code.
     * @param code Code for promotion(s) to delete.
     */
    public function DeletePromo(string $code)
    {
        $response = $this->Request('admin/delete_promo', ['code' => $code]);

        if(false === $response ||
            !is_object($response) ||
            !property_exists($response, 'error'))
        {
            return false;
        }

        return $response;
    } // function DeletePromo

    /**
     * A function to be overrided in the implementation of the API.
     * Called at the end of every Request();
     */
    protected function SaveSession()
    {
        // Extend this class and implement if you need a session.
    } // function SaveSession
} // class Session
